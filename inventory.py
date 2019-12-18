#!/usr/bin/env python3

from netmiko import ConnectHandler
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException)
from paramiko.ssh_exception import SSHException
from ips import get_ip_list
from ipaddress import ip_network
from nmap import PortScanner
import config as cfg
from json import dumps, load
from time import time
from datetime import timedelta, date
from re import compile
# import traceback
from netaddr import EUI, mac_unix_expanded
from netaddr.core import NotRegisteredError
from csv import DictWriter
from pathlib import Path


start = time()
not_connected = []
clubs = []
mac_ouis = []
additional_ids = []

today = date.today()


def connect(ip):
    """Connects to router using .1 address from each ip router from ip_list.

    Args:
        ip - Router IP in x.x.x.1.

    Returns:
        Netmiko connection object.

    Raises:
        Does not raise an error. If connection is unsuccessful,
        None is returned.
    """
    print('\n\nScanning IP {}'.format(ip))
    for _ in range(1):
        for attempt in range(2):
            startconn = time()
            try:
                net_connect = ConnectHandler(device_type='cisco_ios',
                                             host=ip,
                                             username=cfg.ssh['username'],
                                             password=cfg.ssh['password'],
                                             blocking_timeout=20)
                print('\nConnecting... attempt', attempt + 1)
                endconn = time()
                time_elapsed = endconn - startconn
                print('Connection achieved in {} seconds'
                      .format(int(time_elapsed)))
                return net_connect

            except(NetMikoTimeoutException,
                   NetMikoAuthenticationException,
                   SSHException,
                   OSError,
                   ValueError,
                   EOFError):

                # traceback.print_exc()
                # if connection fails and an Exception is raised,
                # scan ip to see if port 22 is open,
                # if it is open try to connect again
                # if it is closed, return None and exit
                nmap_args = 'p22'
                scanner = PortScanner()
                scanner.scan(hosts=ip, arguments=nmap_args)

                for ip in scanner.all_hosts():

                    if scanner[ip].has_tcp(22):

                        if scanner[ip]['tcp'][22]['state'] == 'closed':
                            print('port 22 is showing closed for ' + (ip))
                            not_connected.append(ip)
                            return None
                        else:
                            print('Port 22 is open ')
                            break
                    else:
                        print('port 22 is closed for ' + (ip))
                        continue
                print('Connecting... attempt', attempt + 1)
                if attempt == 0:
                    print('Error, Trying to connect to {} again '.format(ip))

        # exhausted all tries to connect, return None and exit
        print('Connection to {} is not possible: '.format(ip))
        not_connected.append(ip)
        return None


def get_router_info(conn, host):
    """Sends command to router to retrieve its arp-table, extracting all
    devices' mac-addresses and combines this with additional device
    information in a list of dictionaries per location.

    Args:
        conn - Connection object
        host - device IP

    Returns:
        List of devices with device information in dictionary format.

        Example output per device:
        {'IP': 'x.x.x.x',
         'Location': '',
         'Asset Tag': '000P-ABCD-000-000',
         'Category': 'Phone',
         'Manufacturer': 'Cisco',
        'Hostname': 'name@name.com',
         'Mac Address': 'XX:XX:XX:XX:XX:XX',
         'Status': 'up'}

    Raises:
        Does not raise an error. If router information cannot be retrieved,
        a dictionary containing the host, club and status is appended to a
        list of failed results for investigation.
    """
    start2 = time()
    club_result = club_id(conn, host)
    upd_baseline = False
    results = []  # main inventory results
    f_results = []  # list of failed results
    mac_regex = compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = compile(r'(?:\d+\.){3}\d+')
    not_added = []

    for _ in range(1):

        for attempt2 in range(2):

            if conn is not None:

                try:
                    arp_table = conn.send_command('sh arp')
                    arp_list = arp_table.splitlines()
                    print('Sending command to router... attempt', attempt2 + 1)

                    for item in arp_list:
                        counter = 0
                        ip_result = ip_regex.search(item)
                        mac_result = mac_regex.search(item)

                        if ip_result is not None and mac_result is not None:

                            ip_result = ip_result.group(0)
                            mac_result = mac_result.group(0)
                            mac_result = mac_address_format(mac_result)

                            vendor = get_oui_vendor(mac_result)
                            device_type = cfg.get_device_type(ip_result,
                                                              club_result,
                                                              vendor)

                            octets = ip_result.split('.')
                            last_octet = int(octets[-1])
                            first_octet = int(octets[0])

                            hostname = get_hostnames(ip_result)

                            model_name = cfg.model_name(device_type, vendor)

                            club_number = club_num(club_result)

                            asset_tag = asset_tag_gen(ip_result,
                                                      club_number,
                                                      club_result,
                                                      mac_result,
                                                      vendor)

                            if hostname is None:
                                continue

                            # for main results
                            host_info = {'ID': club_number,
                                         'IP': ip_result,
                                         'Location': club_result,
                                         'Asset Tag': asset_tag,
                                         'Category': device_type,
                                         'Manufacturer': vendor,
                                         'Model Name': model_name,
                                         'Hostname': hostname['hostnames'],
                                         'Mac Address': mac_result,
                                         'Status': hostname['status']}

                            # The first value added to 'results'
                            # is the router value. This is only added if the
                            # host IP is 10.x.x.1.
                            # Subsequently, the rest of the mac values
                            # are compared to the first value.
                            # If the mac address is the same,
                            # values are not written to 'results' to avoid
                            # duplicate values from final list.

                            if len(results) == 0:
                                if first_octet == 10 and last_octet == 1:
                                    results.append(host_info)

                                else:
                                    not_added.append(host_info)
                                    continue

                            else:
                                if (host_info['Mac Address'] !=
                                        results[0]['Mac Address']):
                                    results.append(host_info)

                                else:
                                    continue

                            updated_id = id_compare_update(results,
                                                           club_number,
                                                           counter)

                            results[-1]['ID'] = updated_id
                            print(upd_baseline)

                    # when the first value in sh arp is not 10.x.x.1 items
                    # are added to not_added list until it finds the router.
                    # Then, not_added items mac's are compared to router
                    # mac's, and if different, added to results to avoid
                    # duplicate values

                    if not_added != 0:
                        for itm in not_added:
                            if itm['Mac Address'] != results[0]['Mac Address']:
                                results.append(itm)

                    clubs.append(club_result)
                    break

                except(OSError):

                    if attempt2 == 0:
                        print('Could not send cmd "sh arp", trying again')
                        continue

                    else:
                        print('Could not get arp table ' + (host))
                        not_connected.append(host)
                        failed_results = {'Host': host,
                                          'Location': club_result,
                                          'Status': 'could not get arp table'}
                        f_results.append(failed_results)  # for debugging

    end2 = time()
    runtime2 = end2 - start2
    print('Club devices information was received in', runtime2)
    return results


def id_compare_update(results, club_number, counter):
    """Returns a ID for each host

        Args:
            results = list of results
            club_number = numerical value for club
            counter = to increment IDs

        Returns:
            ID - generated ID

        Raises:
            Does not raise an error. If the ID does not contain all
            needed information, it will return base values for result_id.
    """
    last_results = results[-1]

    # open baseline json to compare to prior scans
    try:
        output = open(str(Path(__file__).parent) +
                      '/baselines/baseline_scan_{}.json'
                      .format(results[0]['Location']))
        baseline = load(output)
        output.close()

        # last results updated_id = club_number + length of results
        result_id = (str(club_number) + str(len(results)))

        # returns dictionary item if ['ID'] matches result_id, None otherwise
        dict_item_id = next((item for item in baseline if item['ID'] ==
                             result_id), None)

        dict_item_mac = next((itm for itm in baseline if itm['Mac Address'] ==
                              results[-1]['Mac Address']), None)

        # if ID is found in baseline
        if dict_item_id is not None:

            # if mac address does not match mac address in baseline
            if last_results['Mac Address'] != dict_item_id['Mac Address']:

                # if mac address is not found
                if dict_item_mac is None:
                    # create a new id
                    result_id = club_number + str(len(baseline) + 1 + counter)
                    additional_ids.append(result_id)
                    counter += 1
                    get_router_info.upd_baseline = True

                # if mac address is found with a different ID
                else:
                    # update result_id with old baseline ID
                    result_id = dict_item_mac['ID']

        # if ID is not found
        else:
            # if mac address is found in other items
            if dict_item_mac is not None:
                # revert to previous ID number
                result_id = dict_item_mac['ID']

            else:
                # if ID is not found and Mac Address is not found, add new ID
                result_id = club_number + str(len(baseline) + 1 + counter)
                additional_ids.append(result_id)
                counter += 1
                get_router_info.upd_baseline = True

    except FileNotFoundError:
        result_id = (str(club_number) + str(len(results)))

    return result_id


def write_to_files(results, header_added, host):
    """Function to print and add results to .json and .csv files

    Args:
        results - list returned from get_router_info() for each location
        header_added - boolean value used to avoid multiple headers in csv file

    Returns:
        Does not return anything. Function writes to files.

    Raises:
        Does not raise an error. File is created when function is called and
        if file already exists, results list is appended to
        end of existing file.
    """

    if len(results) != 0:
        for item in results:
            print(item)

        print('\nWriting {} results to files...'
              .format(results[0]['Location']))

        club_output = open(str(Path(__file__).parent) +
                           '/full_scans/full_scan{}.json'
                           .format(today.strftime('%m-%d')), 'a+')
        club_output.write(dumps(results))
        club_output.close()

        keys = results[0].keys()

        try:
            club_base_file = open(str(Path(__file__).parent) +
                                  '/baselines/baseline_scan_{}.json'
                                  .format(results[0]['Location']))
            club_base_file.close()

        except FileNotFoundError:
            cl_base = open(str(Path(__file__).parent) +
                           '/baselines/baseline_scan_{}.json'
                           .format(results[0]['Location']), 'w+')
            cl_base.write(dumps(results))
            cl_base.close()

        with open(str(Path(__file__).parent) +
                  '/full_scans/full_scan{}.csv'
                  .format(today.strftime('%m-%d')), 'a') as csvfile:
            csvwriter = DictWriter(csvfile, keys)
            if header_added is False:
                csvwriter.writeheader()
            csvwriter.writerows(results)

    else:
        print('No results received from router')
        not_connected.append(host)


def update_baseline(results):
    output2 = open(str(Path(__file__).parent) +
                   '/baselines/baseline_scan_{}.json'
                   .format(results[0]['Location']), 'a+')
    output2.close()

    output2 = open(str(Path(__file__).parent) +
                   '/baselines/baseline_scan_{}.json'
                   .format(results[0]['Location']), 'w')
    output2.write(dumps(results))
    output2.close()


def get_oui_vendor(mac):
    """Returns vendor for each device based on mac address

    Args:
        mac - device mac-address

    Returns:
        A string of the associated vendor name

    Raises:
        No error is raised. If there is no vendor found,
        'null' is returned.
    """

    oui_str = mac_oui(mac)

    try:
        oui = EUI(mac).oui
        vendor = oui.registration().org

        return vendor

    # Some of the OUIs are not included in the IEEE.org txt used in netaddr.
    # Those OUIs not included are added in config.py and are gatherered
    # from WireShark. The vendor list is hardcoded because it is rather small.

    except(NotRegisteredError):
        vendor = 'null'

        if oui_str in cfg.cisco:
            vendor = 'Cisco Systems, Inc'
        if oui_str in cfg.dell:
            vendor = 'Dell Inc.'
        if oui_str in cfg.asustek:
            vendor = 'AsustekC ASUSTek COMPUTER INC.'
        if oui_str in cfg.HeFei:
            vendor = 'LcfcHefe LCFC(HeFei) Electronics Technology co., ltd'
        if oui_str in cfg.meraki:
            vendor = 'CiscoMer Cisco Meraki'
        if oui_str in cfg.winstron:
            vendor = 'Wistron Infocomm (Zhongshan) Corporation'
        if oui_str in cfg.null:
            vendor = 'Not Defined'

        mac_ouis.append(oui_str)

        return vendor


def mac_oui(mac):
    """Returns OUI from mac address passed in argument

    Args:
        mac - device mac-address

    Returns:
        OUI for mac-address

    Raises:
        No error is raised.
    """
    # get first three octets for oui
    oui = mac[:8]

    return oui


def mac_address_format(mac):
    """Return formatted version of mac address

    Args:
        mac - device mac-address

    Returns:
        Formatted mac-address in format: XX:XX:XX:XX:XX:XX

    Raises:
        No error is raised.
    """
    formatted_mac = EUI(str(mac))
    formatted_mac.dialect = mac_unix_expanded
    formatted_mac = (str(formatted_mac).upper())

    return formatted_mac


def club_id(conn, host):
    """Sends command to router to retrieve location ID information.
    if not found, attempts to get location ID using get_hostnames()

    Args:
        conn - Connection object
        host - Device IP

    Returns:
        club_result - location ID

    Raises:
        Does not raise an error. If router information cannot be retrieved,
        'null' is returned.
    """
    club_rgx = compile(cfg.club_rgx)
    reg_rgx = compile(cfg.reg_rgx)

    club_result = '--'

    for _ in range(1):

        for attempt in range(2):

            if conn is not None:

                try:
                    club_info = conn.send_command('sh cdp entry *')
                    club_result = club_rgx.search(club_info)
                    print('Getting club ID... attempt', attempt + 1)

                    if club_result is None:
                        club_result = reg_rgx.search(club_info)

                    if club_result is not None:
                        club_result = club_result.group(0)

                    if club_result is None:
                        hostname = get_hostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club is not None:
                            club_result = hostname_club.group(0)

                        if hostname_club is None:
                            club_result = 'null'
                    break

                except(OSError):
                    if attempt == 0:
                        print('Could not send command, cdp. Trying again')
                        continue

                    if attempt == 1:
                        print('Getting club_id from nmap hostname')
                        hostname = get_hostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club is not None:
                            club_result = hostname_club.group(0)

                        if hostname_club is None:
                            print('could not get club_id')
                            club_result = 'null'

        club_result = club_result.lower()
        return club_result


def get_hostnames(ip):
    """Scan router for hostname using python-nmap

    Args:
        ip - router IP

    Returns:
        host - a dictionary containing hostname and status retrieved from scan

        {'IP': ip,
         'Hostname': hostname,
         'Status' : status}

    Raises:
        Does not raise an error. If a host is not found, an empty string
        is returned ''.
    """
    hosts = str(ip)
    nmap_args = '-sn'
    scanner = PortScanner()
    scanner.scan(hosts=hosts, arguments=nmap_args)

    for ip in scanner.all_hosts():

        host = {'ip': ip}

        if 'hostnames' in scanner[ip]:
            host['hostnames'] = scanner[ip].hostname()

        if 'status' in scanner[ip]:
            host['status'] = scanner[ip]['status']['state']

        return host


#  Function to return only a site router IP which ends in '.1'.
def get_site_router(ip):
    """Returns router IP when called

    Args:
        ip - ip from ips.py. Looped in main()

    Returns:
        first_host - first host from given subnet ending in x.x.x.1,
        this is the router ip.

    Raises:
        Does not raise an error.
    """
    site_hosts = ip_network(ip)
    first_host = next(site_hosts.hosts())
    return(first_host)


def club_num(club_result):
    """Returns a generated ID for each club asset

    Args:
        club_result - Location ID from club_id()

    Returns:
        club_number = numeric value for each club

    Raises:
        Does not raise an error if club number is not found,
        it will return '000'
    """
    club_number = 'null'

    club_n_regex = compile(r'((?<=club)[\d]{3})')
    reg_n_regex = compile(r'((?<=reg-)[\d]{3})')

    # Extract club number for regional offices
    club_id = reg_n_regex.search(club_result)

    # if regional office pattern not found
    if club_id is None:
        # Extract club number for clubs
        club_id = club_n_regex.search(club_result)
        # If club pattern is found
        if club_id is not None:
            club_id = club_id.group(0)
            club_number = club_id
    else:
        # If regional Office pattern found, Club Number = regional_num (config)
        club_number = cfg.regional_num[club_result]

    return club_number


def asset_tag_gen(host, club_number, club_result, mac, vendor):
    """Returns a generated asset tag for the host

    Args:
        host - device IP
        club_result - Location ID from club_id()
        mac - device mac-address

    Returns:
        asset_tag - generated asset tag

    Raises:
        Does not raise an error. If the asset tag does not contain all
        needed information, it will contain base values defined.
    """
    # initialize assets with base values
    asset1 = club_number
    asset2 = 'N'
    asset3 = 'ABCD'
    asset4 = '000-000'

    # Extract host IP's last two octets to be added to asset4
    octets = host.split('.')
    last_octet = octets[-1]
    third_octet = octets[2]

    asset4 = ('-' + third_octet + '-' + last_octet)

    # Extract host's mac address last 4 characters to be added to asset3
    mac_third = mac[-5:-3]
    mac_fourth = mac[-2:]

    asset3 = ('-' + mac_third + mac_fourth)
    loc_num_rgx = compile(r'([\d]{3})')

    if club_number != 'null':
        # club_number is the return from club_num()
        asset1 = club_number

    else:
        # Extract location number
        club_id = loc_num_rgx.search(club_result)
        if club_id is not None:
            club_id = club_id.group(0)
            asset1 = club_id
        else:
            asset1 = '000'

    # Extract first letter of device type for asset2
    device_type = cfg.get_device_type(host, club_result, vendor)
    asset2 = device_type[0].upper()

    # Generated asset tag is the concatenation of all assets
    asset_tag = (asset1 + asset2 + asset3 + asset4)

    return asset_tag


def main(ip_list):
    """main function to run script, using get_ip_list from ips.py
    or using a specific list of ips

    Args:
        None

    Returns:
        None

    Raises:
        Does not raise an error.
    """

    header_added = False

    print(cfg.intro1)
    print(cfg.intro2)

    for ip in ip_list:
        clb_runtime_str = time()
        router_connect = connect(str(get_site_router(ip)))

        if router_connect is not None:
            results = get_router_info(router_connect, str(get_site_router(ip)))
            write_to_files(results, header_added, str(get_site_router(ip)))

            router_connect.disconnect()

        clb_runtime_end = time()
        clb_runtime = clb_runtime_end - clb_runtime_str
        clb_runtime = str(timedelta(seconds=int(clb_runtime)))
        header_added = True
        try:
            if router_connect is not None:
                print('\n{} Scan Runtime: {} '
                      .format(results[0]['Location'], clb_runtime))
            else:
                print('\nClub Scan Runtime: {} '.format(clb_runtime))
        except:
            print('\nClub Scan Runtime: {} '.format(clb_runtime))

    print('\nThe following {} hosts were not scanned'
          .format(len(not_connected)))
    print(not_connected)

    print('\nThe following {} clubs were scanned'.format(len(clubs)))
    print(clubs)


ip_list = get_ip_list()
ip_list = ['10.6.3.0/24', '10.11.139.0/24', '10.16.11.0/24', '10.96.0.0/24']

main(ip_list)

end = time()
runtime = end - start
runtime = str(timedelta(seconds=int(runtime)))
print('\nScript Runtime: {} '.format(runtime))
