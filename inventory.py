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
from json import dumps
from time import time
from datetime import timedelta
from re import compile
# import traceback
from netaddr import EUI, mac_unix_expanded
from netaddr.core import NotRegisteredError
from csv import DictWriter

start = time()
not_connected = []
clubs = []
mac_ouis = []


def connect(ip):
    """Connects to router using .1 address from each ip router from ip_list.

    Args:
        ip - Router IP in x.x.x.1.

    Returns:
        Netmiko connection object.

    Raises:
        Does not raise an error. If connection is unsuccessful, None is returned.
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
                print('Connection achieved in {} seconds'.format(int(time_elapsed)))
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


def getRouterInfo(conn, host):
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
    club_result = clubID(conn, host)

    results = []
    f_results = []
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

                        ip_result = ip_regex.search(item)
                        mac_result = mac_regex.search(item)

                        if ip_result is not None and mac_result is not None:

                            ip_result = ip_result.group(0)
                            mac_result = mac_result.group(0)
                            mac_result = macAddressFormat(mac_result)

                            vendor = getOuiVendor(mac_result)
                            deviceType = cfg.getDeviceType(ip_result,
                                                           club_result,
                                                           vendor)

                            octets = ip_result.split('.')
                            last_octet = int(octets[-1])
                            first_octet = int(octets[0])
                            
                            hostname = getHostnames(ip_result)

                            model_name = cfg.modelName(deviceType, vendor)

                            asset_tag = assetTagGenerator(ip_result,
                                                          club_result,
                                                          mac_result,
                                                          vendor)

                            if hostname is None:
                                continue

                            subnet_mac = {'IP': ip_result,
                                          'Location': club_result,
                                          'Asset Tag': asset_tag,
                                          'Category': deviceType,
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
                                    results.append(subnet_mac)
                                else:
                                    not_added.append(subnet_mac)

                            if (len(results) != 0 and
                                    subnet_mac['Mac Address'] != results[0]['Mac Address']):
                                results.append(subnet_mac)

                    # when the first value in sh arp is not 10.x.x.1 items
                    # are added to not_added list until it finds the router.
                    # Then, not_added items mac's are compared to router
                    # mac's, and if different, added to results to avoid
                    # duplicate values

                    if not_added != 0:
                        for item in not_added:
                            if item['Mac Address'] != results[0]['Mac Address']:
                                results.append(item)

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
                        f_results.append(failed_results)

    end2 = time()
    runtime2 = end2 - start2
    print('Club devices information was received in', runtime2)
    return results


def writeToFiles(results, header_added):
    """Function to print and add results to .json and .csv files

    Args:
        results - list returned from getRouterInfo() for each location
        header_added - boolean value used to avoid multiple headers in csv file

    Returns:
        Does not return anything. Function writes to files.

    Raises:
        Does not raise an error. File is created when function is called and
        if file already exists, results list is appended to end of existing file
    """

    if len(results) != 0:
        for item in results:
            print(item)

        print('\nWriting {} results to files...'.format(results[0]['Location']))

        output = open('scan11-15.json', 'a+')
        output.write(dumps(results))
        output.close()

        keys = results[0].keys()

        with open('scan11-15.csv', 'a') as csvfile:
            csvwriter = DictWriter(csvfile, keys)
            if header_added is False:
                csvwriter.writeheader()
            csvwriter.writerows(results)


def getOuiVendor(mac):
    """Returns vendor for each device based on mac address

    Args:
        mac - device mac-address

    Returns:
        A string of the associated vendor name

    Raises:
        No error is raised. If there is no vendor found,
        'null' is returned.
    """
    oui = macOUI(mac)

    try:
        mac_oui = EUI(mac).oui
        vendor = mac_oui.registration().org

        return vendor

    # Some of the OUIs are not included in the IEEE.org txt used in netaddr.
    # Those OUIs not included are added in config.py and are gatherered
    # from WireShark. The vendor list is hardcoded because it is rather small.

    except(NotRegisteredError):
        vendor = 'null'

        if oui in cfg.cisco:            
            vendor = 'Cisco Systems, Inc'
        if oui in cfg.dell:
            vendor = 'Dell Inc.'
        if oui in cfg.asustek:
            vendor = 'AsustekC ASUSTek COMPUTER INC.'
        if oui in cfg.HeFei:
            vendor = 'LcfcHefe LCFC(HeFei) Electronics Technology co., ltd'
        if oui in cfg.meraki:
            vendor = 'CiscoMer Cisco Meraki'
        if oui in cfg.winstron:
            vendor = 'Wistron Infocomm (Zhongshan) Corporation'
        if oui in cfg.null:
            vendor = 'Not Defined'

        mac_ouis.append(oui)

        return vendor


def macOUI(mac):
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


def macAddressFormat(mac):
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


def clubID(conn, host):
    """Sends command to router to retrieve location ID information.
    if not found, attempts to get location ID using getHostNames()

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
                        hostname = getHostnames(host)
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
                        print('Getting clubID from nmap hostname')
                        hostname = getHostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club is not None:
                            club_result = hostname_club.group(0)

                        if hostname_club is None:
                            print('could not get clubID')
                            club_result = 'null'

        club_result = club_result.lower()
        return club_result


def getHostnames(ip):
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
def getSiteRouter(ip):
    """Returns router IP when called

    Args:
        ip - ip from ips.py. Looped in main()

    Returns:
        firstHost - first host from given subnet ending in x.x.x.1,
        this is the router ip.

    Raises:
        Does not raise an error.
    """
    siteHosts = ip_network(ip)
    firstHost = next(siteHosts.hosts())
    return(firstHost)


def assetTagGenerator(host, club_result, mac, vendor):
    """Returns a generated asset tag for the host

    Args:
        host - device IP
        club_result - Location ID from clubID()
        mac - device mac-address

    Returns:
        asset_tag - generated asset tag

    Raises:
        Does not raise an error. If the asset tag does not contain all
        needed information, it will contain base values defined.
    """
    # initialize assets with base values
    asset1 = '000'
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

    club_n_regex = compile(r'([0-9]{3})')
    reg_n_regex = compile(r'([REG]{3})')

    # Extract club number to be used in asset1 (regional offices)
    club_id = reg_n_regex.search(club_result)

    if club_id is None:
        # Extract club number for asset1 (clubs)
        club_id = club_n_regex.search(club_result)

        if club_id is not None:

            club_id = club_id.group(0)
            asset1 = club_id

        else:
            asset1 = club_result
    else:
        club_id = club_id.group(0)
        asset1 = club_result[3:]

    # Extract first letter of device type for asset2
    device_type = cfg.getDeviceType(host, club_result, vendor)
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
        router_connect = connect(str(getSiteRouter(ip)))

        if router_connect is not None:
            results = getRouterInfo(router_connect, str(getSiteRouter(ip)))
            writeToFiles(results, header_added)

            router_connect.disconnect()

        clb_runtime_end = time()
        clb_runtime = clb_runtime_end - clb_runtime_str
        clb_runtime = str(timedelta(seconds = int(clb_runtime)))
        header_added = True
        try:
            if router_connect is not None:
                print('\n{} Scan Runtime: {} '.format(results[0]['Location'], clb_runtime))
            else:
                print('\nClub Scan Runtime: {} '.format(clb_runtime))
        except:
            print('\nClub Scan Runtime: {} '.format(clb_runtime))

    print('\nThe following {} hosts were not scanned'.format(len(not_connected)))
    print(not_connected)

    print('\nThe following {} clubs were scanned'.format(len(clubs)))
    print(clubs)


ip_list = ['10.16.15.0/24', '10.10.3.0/24', '10.11.139.0/24', '10.16.11.0/24', '10.96.0.0/24']
# ip_list = get_ip_list()
main(ip_list)

end = time()
runtime = end - start
runtime = str(timedelta(seconds = int(runtime)))
print('\nScript Runtime: {} '.format(runtime))
