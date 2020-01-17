#!/usr/bin/env python3

from os import path, listdir
from ipaddress import ip_network
from json import dumps, load
from csv import DictWriter
from pathlib import Path
from time import time
from re import compile
from datetime import timedelta, date
# import traceback

from nmap import PortScanner
from paramiko.ssh_exception import SSHException
from netmiko import ConnectHandler
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException)

from ips import get_ip_list
import config as cfg


start = time()
today = date.today()
not_connected = []
clubs = []
additional_ids = []


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
            diff(results)
            router_connect.disconnect()
        clb_runtime_end = time()
        clb_runtime = clb_runtime_end - clb_runtime_str
        clb_runtime = str(timedelta(seconds=int(clb_runtime)))
        header_added = True
        if router_connect is not None:
            print('\n{} Scan Runtime: {} '
                  .format(results[0]['Location'], clb_runtime))
        else:
            print('\nClub Scan Runtime: {} '.format(clb_runtime))
    print('\nThe following {} hosts were not scanned'
          .format(len(not_connected)))
    print(not_connected)
    print('\nThe following {} clubs were scanned'.format(len(clubs)))
    print(clubs)


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
    results = []  # main inventory results
    f_results = []  # list of failed results
    mac_regex = compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = compile(r'(?:\d+\.){3}\d+')
    not_added = []
    counter = 0

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
                            mac_result = cfg.mac_address_format(mac_result)
                            vendor = cfg.get_oui_vendor(mac_result)
                            device_type = cfg.get_device_type(
                                ip_result,
                                club_result,
                                vendor
                            )
                            octets = ip_result.split('.')
                            last_octet = int(octets[-1])
                            first_octet = int(octets[0])
                            hostname = get_hostnames(ip_result)
                            model_name = cfg.model_name(device_type, vendor)
                            club_number = club_num(club_result)
                            asset_tag = asset_tag_gen(
                                ip_result,
                                club_number,
                                club_result,
                                mac_result,
                                vendor
                            )

                            if hostname is None:
                                continue

                            # for main results
                            host_info = {
                                'ID': club_number,
                                'IP': ip_result,
                                'Location': club_result,
                                'Asset Tag': asset_tag,
                                'Category': device_type,
                                'Manufacturer': vendor,
                                'Model Name': model_name,
                                'Hostname': hostname['hostnames'],
                                'Mac Address': mac_result,
                                'Status': hostname['status']
                            }

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
                            updated_id = id_compare_update(
                                results,
                                club_number,
                                counter
                            )
                            results[-1]['ID'] = updated_id

                    # when the first value in sh arp is not 10.x.x.1 items
                    # are added to not_added list until it finds the router.
                    # Then, not_added items mac's are compared to router
                    # mac's, and if different, added to results to avoid
                    # duplicate values

                    if not_added != 0:
                        for itm in not_added:
                            if itm['Mac Address'] != results[0]['Mac Address']:
                                results.append(itm)
                                print('good so far14')
                    clubs.append(club_result)
                    print('Results complete')
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
        # writing full scan to .json
        club_output = open(
            './full_scans/full_scan{}.json'.format(
                today.strftime('%Y-%m-%d')), 'a+')
        club_output.write(dumps(results))
        club_output.close()
        keys = results[0].keys()
        # make directory that will contain individual scans by club
        mydir = path.join('./baselines/{}'.format(results[0]['Location']))
        mydir_obj = Path(mydir)
        mydir_obj.mkdir(parents=True, exist_ok=True)
        club_base_file = open(
            mydir + '/{}_{}.json'.format(results[0]['Location'],
                                         today.strftime("%Y-%m-%d")), 'w+')
        # dump .json file for each raw club scan in directory
        club_base_file.write(dumps(results))
        club_base_file.close()
        # create .csv file with full scan
        with open('./full_scans/full_scan{}.csv'
                  .format(today.strftime('%m-%d')), 'a') as csvfile:
            csvwriter = DictWriter(csvfile, keys)
            if header_added is False:
                csvwriter.writeheader()
            csvwriter.writerows(results)
    else:
        print('No results received from router')
        not_connected.append(host)


def diff(results):
    """ Function to get differences between current and prior scans
    once differences are found, differences are written in delta files
    by date of scan.
    Function also returns a list of all deltas.

    Args:
        results - current scan device information by location

    Returns:
        all_diff - all differences between scans,
                   to include additions, removals and updated information

    Raises:
        does not raise an error, if there is no scan to compare to,
        or there is a problem getting difference,
        function returns None

    """
    diff = []
    diff2 = []
    club = results[0]['Location']
    baseline_update = []
    baseline_remove = []
    baseline_add = []
    baseline_review = []
    baseline = load_baseline(results)

    if baseline is None:
        print('No prior baseline found')
        return None
    print('Loading prior baseline')
    # make directory that will contain all deltas by date
    mydir = path.join('./delta')
    mydir_obj = Path(mydir)
    mydir_obj.mkdir(parents=True, exist_ok=True)
    # create file for individual delta scans
    diff_file = open(mydir + '/{}.json'
                     .format(today.strftime("%Y-%m-%d")), 'a+')
    # file to write status of differences as they happen
    status_file = open('scan_status_{}'
                       .format(today.strftime('%Y-%m-%d')), 'a+')
    status_file.write(club.upper())
    # find differences between the two lists, dump a new baseline
    # and return the difference
    # to update baseline
    diff = filter(lambda item: item not in baseline, results)
    diff2 = filter(lambda item: item not in results, baseline)
    # add all differences in one list
    all_diff = list(diff)
    all_diff.extend(item for item in diff2 if item not in all_diff)
    print(all_diff)
    # dump all deltas not in baseline in .json file for each club in directory
    diff_file.write(dumps(list(all_diff)))
    diff_file.close()
    # if there are no differences add message to status file
    if len(all_diff) == 0:
        status_file.write('\nNo changes since prior scan for {} '.format(club))
        print('No changes since prior scan for {} '.format(club))
    # get item FROM RESULTS that cannot be found in baseline and compare each
    # key to respective item in baseline one by one
    if diff is not None:
        # for each item different in baseline
        for diff_item in diff:
            print('diff 1')
            # returns dict item if ID found in baseline,
            # returns None if not found
            baseline_item_id = next((item for item in baseline if item['ID'] ==
                                     diff_item['ID']), None)
            # returns dict item if mac address is found in baseline
            baseline_item_mac = next((item for item in baseline if
                                      item['Mac Address'] ==
                                      diff_item['Mac Address']), None)
            # if diff item matches baseline ID, Mac, Location, changes
            # do not need review and inventory can be updated
            if baseline_item_id is not None and baseline_item_mac is not None:
                if (baseline_item_id['ID'] == baseline_item_mac['ID'] and
                        diff_item['Location'] == baseline_item_id['Location']
                        and baseline_item_id['ID'] == diff_item['ID'] and
                        baseline_item_mac['Mac Address'] ==
                        diff_item['Mac Address']):
                    # Changes do not need review. Add item for baseline update
                    print('Changes do not need review')
                    status_file.write('Device with ID {} and Mac Address {}'
                                      'updated\n'
                                      .format(diff_item['ID'],
                                              diff_item['Mac Address']))
                    baseline_update.append(diff_item)
                    print('diff 2')
            # if ID and Mac are not found in baseline
            # new item to be added to baseline
            elif baseline_item_id is None and baseline_item_mac is None:
                print('new item to be added to baseline')
                status_file.write('New device with ID {} and Mac Address {}'
                                  'added\n'
                                  .format(diff_item['ID'],
                                          diff_item['Mac Address']))
                baseline_add.append(diff_item)
                print('diff 3')
            # ID found with different Mac Address
            elif baseline_item_id is not None and baseline_item_mac is None:
                if baseline_item_id['Mac Address'] != diff_item['Mac Address']:
                    status_file.write('Device with ID {} and Mac Address {} '
                                      'has different Mac Address {} '
                                      'in baseline, needs review\n'
                                      .format(diff_item['ID'],
                                              diff_item['Mac Address'],
                                              baseline_item_id['Mac Address']))
                baseline_review.append(diff_item)
                print('diff 4')
            # Mac Address found with different ID
            elif baseline_item_id is None and baseline_item_mac is not None:
                if baseline_item_mac['ID'] != diff_item['ID']:
                    status_file.write('New device with ID {} '
                                      'and Mac Address {} '
                                      'has different ID {} in baseline, '
                                      'Needs review\n'
                                      .format(diff_item['ID'],
                                              diff_item['Mac Address'],
                                              baseline_item_mac['ID']))
                baseline_review.append(diff_item)
    if len(all_diff) != 0:
        print('Baseline_review', baseline_review)
        print('Baseline_add', baseline_add)
        print('Baseline_update', baseline_update)
        print('Baseline_remove', baseline_remove)
    if results[0]['Hostname'] != '':
        if results[0]['Location'] not in results[0]['Hostname']:
            status_file.write('\nLocation {} does not match Hostname {}'
                              .format(results[0]['Location'],
                                      results[0]['Hostname']))
            print('location {} does not match hostname ------ {} '
                  .format(results[0]['Location'], results[0]['Hostname']))

    return all_diff


def id_compare_update(results, club_number, counter):
    """Returns a ID for each host.
    This function returns a generated ID after it compares it to ID's
    on baseline, to avoid duplicate IDs.

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
    baseline_ids = []
    # open baseline json to compare to prior scans
    baseline = load_baseline(results)
    # last results updated_id = 'club_number' + 'length of results'
    result_id = (str(club_number) + str(len(results)))
    if baseline is None:
        return result_id
    # add all baseline IDs to list
    baseline_ids = [int(item['ID']) for item in baseline]
    # get highest ID in list
    baseline_ids_max = max(baseline_ids)
    # returns dictionary item if ['ID'] matches result_id, None otherwise
    dict_item_id = next((item for item in baseline if item['ID'] ==
                         result_id), None)
    # returns dictionary item if ['Mac Address] matches mac in last result
    # returns none if the mac address is not found in last result
    dict_item_mac = next((itm for itm in baseline if itm['Mac Address'] ==
                          results[-1]['Mac Address']), None)
    # if ID is found in baseline
    if dict_item_id is not None:
        # if mac address does not match mac address in item found
        if last_results['Mac Address'] != dict_item_id['Mac Address']:
            # if mac address is not found anywhere else in baseline
            if dict_item_mac is None:
                # create a new id
                result_id = club_number + str(len(baseline) + 1 + counter)
                print('id found but mac doesnt match')
                # make sure id created is not in baseline
                while int(result_id) <= baseline_ids_max:
                    result_id = result_id + 1
                additional_ids.append(result_id)
            # if mac address is found with a different ID in baseline
            else:
                # update result_id with old baseline ID
                result_id = dict_item_mac['ID']

    # if ID is not found in baseline
    else:
        # if mac address is found in other items
        if dict_item_mac is not None:
            # revert to previous ID number
            result_id = dict_item_mac['ID']
        else:
            # if ID is not found and Mac Address is not found, add new ID
            result_id = club_number + str(len(baseline) + 1 + counter)
            print('id not found, mac doesnt match')
            # make sure id created is not in baseline
            while int(result_id) <= baseline_ids_max:
                result_id = result_id + 1
            additional_ids.append(result_id)

    return result_id


def load_baseline(results):
    """Opens and loads prior scan as baseline for use in diff()
    and id_compare_update()

        Args:
            results = list of results

        Returns:
            baseline - list of dictionary items from baseline in prior scans

        Raises:
            Does not raise an error. If there is no baseline, returns None
    """
    club = results[0]['Location']

    try:
        club_bsln_path = './baselines/{}'.format(club)
        # get list of all files in club baseline directory
        list_dir = listdir(club_bsln_path)
        if len(list_dir) > 1:
            # sort list to find latest
            sorted_list_dir = sorted(list_dir)
            last_baseline = sorted_list_dir[-1]
            # if scan is perfomed more than once in a day, make sure baseline
            # still the prior scan performed in an earlier date
            if today.strftime("%Y-%m-%d") in last_baseline:
                if len(list_dir) >= 2:
                    last_baseline = sorted_list_dir[-2]
                else:
                    return None
            # full path of baseline to use for difference
            baseline_path = path.join(club_bsln_path, str(last_baseline))
        else:
            baseline_path = path.join(club_bsln_path, str(list_dir[0]))

        output = open(baseline_path)
        baseline = load(output)
        output.close()

        return baseline

    except FileNotFoundError:
        return None


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
        it will return 'null'
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
    asset_tag = (asset1 + asset2 + asset3)

    return asset_tag


ip_list = get_ip_list()

main(ip_list)

end = time()
runtime = end - start
runtime = str(timedelta(seconds=int(runtime)))
print('\nScript Runtime: {} '.format(runtime))
