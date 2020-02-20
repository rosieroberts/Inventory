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
    all_diff = []
    all_api_payload_items = []
 
    header_added = False

    print(cfg.intro1)
    print(cfg.intro2)

    for ip in ip_list:
        clb_runtime_str = time()
        router_connect = connect(str(get_site_router(ip)))
        if router_connect:
            results = get_router_info(router_connect, str(get_site_router(ip)))
            all_diff = diff(results, load_baseline(results))
            if  all_diff:
                all_api_payload_items = api_payload(all_diff[0], all_diff[1], all_diff[2])
            write_to_files(results, header_added, str(get_site_router(ip)))
            router_connect.disconnect()
        clb_runtime_end = time()
        clb_runtime = clb_runtime_end - clb_runtime_str
        clb_runtime = str(timedelta(seconds=int(clb_runtime)))
        header_added = True
        if router_connect:
            print('\n{} Scan Runtime: {} '
                  .format(results[0]['Location'], clb_runtime))
        else:
            print('\nClub Scan Runtime: {} '.format(clb_runtime))
    print('\nThe following {} hosts were not scanned'
          .format(len(not_connected)))
    print(not_connected)
    print('\nThe following {} clubs were scanned'.format(len(clubs)))
    print(clubs)
    return all_api_payload_items


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
                            model_number = cfg.models.get(model_name)
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
                                'Model Number': model_number,
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
                                club_number
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
                    clubs.append(club_result)
                    print('Results complete...')
                    for item in results:
                        print(item)
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

    # make directory that will contain all full scans by date
    full_scan_dir = path.join('./full_scans')
    full_scan_dir_obj = Path(full_scan_dir)
    full_scan_dir_obj.mkdir(parents=True, exist_ok=True)

    if len(results) != 0:
        print('\nWriting {} results to files...'
              .format(results[0]['Location']))
        # writing full scan to .json
        club_output = open(
            './full_scans/full_scan{}.json'.format(
                today.strftime('%m-%d-%Y')), 'a+')
        club_output.write(dumps(results, indent=4))
        club_output.close()
        keys = results[0].keys()
        # make directory that will contain individual scans by club
        mydir = path.join('./baselines/{}'.format(results[0]['Location']))
        mydir_obj = Path(mydir)
        mydir_obj.mkdir(parents=True, exist_ok=True)
        club_base_file = open(
            mydir + '/{}_{}.json'.format(results[0]['Location'],
                                         today.strftime('%m-%d-%Y')), 'w+')
        # dump .json file for each raw club scan in directory
        club_base_file.write(dumps(results, indent=4))
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


def diff(results, baseline):
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
    club = results[0]['Location']
    update = []
    remove = []
    review = []
    add = []
    all_diff = []

    if not results:
        print('no results found')
        return None
    if not baseline:
        print('No prior baseline found')
        return None
    if results[0]['Location'] != baseline[0]['Location']:
        print('Club information cannot be compared')
        return None
    # make directory that will contain all deltas by date
    mydir = path.join('./delta')
    mydir_obj = Path(mydir)
    mydir_obj.mkdir(parents=True, exist_ok=True)

    # make directory that will contain all scan statuses by date
    mydir = path.join('./scan_status')
    mydir_obj = Path(mydir)
    mydir_obj.mkdir(parents=True, exist_ok=True)

    # create file to write status of differences as they happen
    status_file = open('./scan_status/scan_{}'
                       .format(today.strftime('%m-%d-%Y')), 'a+')
    if club:
        status_file.write('\n\n')
        status_file.write(club.upper())

    not_in_baseline = list(filter(lambda item: item not in baseline, results))
    not_in_results = list(filter(lambda item: item not in results, baseline))

    if not(not_in_baseline and not_in_results):
        status_file.write('\nNo changes since prior scan for {}\n'
                          .format(club))
        print('No changes since prior scan for {} '.format(club))
        return None

    # FIND what changed since last scan and add to correct list
    # -
    # baseline_review - Any changes except IP and status
    # baseline_add - New Mac Address and ID
    # baseline_update - IP, Status - no review required
    # baseline_remove - Mac Address and IP not found in scan

    # if new scan items are not found in baseline
    if not_in_baseline:
        count = 0
        for diff_item in not_in_baseline:
            count += 1
            print('\nDIFF ITEM', count)
            # find id of different item in baseline,
            # returns dict, otherwise None
            id_in_baseline = next((item for item in baseline if
                                   diff_item['ID'] == item['ID']), None)
            # find mac address of different item in baseline,
            # returns dict, otherwise None
            mac_in_baseline = next((item for item in baseline if
                                    diff_item['Mac Address'] ==
                                    item['Mac Address']), None)

            # if ID for different item is not found in baseline
            if not id_in_baseline:
                # if Mac Address is not found elsewhere in baseline
                if not mac_in_baseline:
                    add.append(diff_item)
                    msg1 = ('\nNew device with ID {} and Mac Address {} '
                            'added\n'
                            .format(diff_item['ID'],
                                    diff_item['Mac Address']))
                    print(msg1)
                    status_file.write(msg1)

                # if mac address is found in baseline with another ID
                if mac_in_baseline:
                    review.append(diff_item)
                    if diff_item['ID'] != mac_in_baseline['ID']:
                        msg2 = ('\nDevice with ID {} and Mac Address {} '
                                '\nchanged to a different ID {}, '
                                '\nneeds review\n'
                                .format(mac_in_baseline['ID'],
                                        diff_item['Mac Address'],
                                        diff_item['ID']))
                        print(msg2)
                        status_file.write(msg2)

            # if ID for different item is found in baseline
            if id_in_baseline:
                # if Mac Address is found in baseline
                if mac_in_baseline:
                    # if items found have the same mac address
                    if (diff_item['Mac Address'] ==
                            id_in_baseline['Mac Address'] and
                            diff_item['ID'] == mac_in_baseline['ID']):
                        update.append(diff_item)
                        # if IP changed
                        if diff_item['IP'] != id_in_baseline['IP']:
                            msg3 = ('\nDevice with ID {} '
                                    'and Mac Address {} '
                                    '\nhas different IP {}, '
                                    '\nhas been updated\n'
                                    .format(diff_item['ID'],
                                            diff_item['Mac Address'],
                                            diff_item['IP']))
                            print(msg3)
                            status_file.write(msg3)

                        else:
                            msg4 = ('\nDevice with ID {} and Mac Address {} '
                                    '\nhas been updated\n '
                                    .format(id_in_baseline['ID'],
                                            id_in_baseline['Mac Address']))
                            print(msg4)
                            status_file.write(msg4)

                    else:
                        review.append(diff_item)
                        msg5 = ('\nDevice with ID {} and Mac Address {} '
                                '\nhas changed to ID {}'
                                'and Mac Address {},'
                                '\nMac Address {} is already in'
                                'baseline with ID {}. '
                                '\nneeds review\n'
                                .format(id_in_baseline['ID'],
                                        id_in_baseline['Mac Address'],
                                        diff_item['ID'],
                                        diff_item['Mac Address'],
                                        mac_in_baseline['Mac Address'],
                                        mac_in_baseline['ID']))
                        print(msg5)
                        status_file.write(msg5)
                else:
                    review.append(diff_item)
                    msg6 = ('\nDevice with ID {} and Mac Address {} '
                            '\nhas a different mac address {}, '
                            '\nneeds review\n'
                            .format(diff_item['ID'],
                                    id_in_baseline['Mac Address'],
                                    diff_item['Mac Address']))
                    print(msg6)
                    status_file.write(msg6)
    # devices from baseline not found in results
    if not_in_results:
        for diff_item in not_in_results:
            # find id of different item in results,
            # returns dict, otherwise None
            id_in_results = next((item for item in results if
                                  diff_item['ID'] == item['ID']), None)
            # find mac address of different item in results,
            # returns dict, otherwise None
            mac_in_results = next((item for item in results if
                                   diff_item['Mac Address'] ==
                                   item['Mac Address']), None)

            # if ID for different item is not found in results
            if not id_in_results:
                # if Mac Address is not found elsewhere in results
                if not mac_in_results:
                    count += 1
                    print('\nDIFF ITEM', count)
                    remove.append(diff_item)
                    msg7 = ('\nDevice with ID {} and Mac Address {} '
                            '\nno longer found, '
                            'has been removed\n'
                            .format(diff_item['ID'],
                                    diff_item['Mac Address']))
                    print(msg7)
                    status_file.write(msg7)

    # if hostname does not match location in scan, write message in status file
    if results[0]['Hostname'] != '':
        if results[0]['Location'] not in results[0]['Hostname']:
            msg8 = ('\nLocation {} does not match Hostname {}\n'
                    .format(club, results[0]['Hostname']))
            print(msg8)
            status_file.write(msg8)

    print('\nREVIEW')
    if review:
        print('Writing Devices to Review')
        # create file for review
        review_file = open(mydir + '/review_{}.json'
                           .format(today.strftime("%m-%d-%Y")), 'a+')
        review_file.write(dumps(list(review), indent=4))
        review_file.close()
        all_diff.extend(review)
        for item in review:
            print(item)
    else:
        print('None')

    print('\nUPDATE')
    if update:
        print('Writing Devices to Update')
        # create file for update
        update_file = open(mydir + '/update_{}.json'
                           .format(today.strftime("%m-%d-%Y")), 'a+')
        update_file.write(dumps(list(update), indent=4))
        update_file.close()
        all_diff.extend(update)
        for item in update:
            print(item)
    else:
        print('None')

    print('\nADD')
    if add:
        print('Writing Devices to Add')
        # create file for add
        add_file = open(mydir + '/add_{}.json'
                        .format(today.strftime("%m-%d-%Y")), 'a+')
        add_file.write(dumps(list(add), indent=4))
        add_file.close()
        all_diff.extend(add)
        for item in add:
            print(item)
    else:
        print('None')

    print('\nREMOVE')
    if remove:
        print('Writing Devices to Remove')
        # create file for remove
        remove_file = open(mydir + '/remove_{}.json'
                           .format(today.strftime("%m-%d-%Y")), 'a+')
        remove_file.write(dumps(list(remove), indent=4))
        remove_file.close()
        all_diff.extend(remove)
        for item in remove:
            print(item)
    else:
        print('None')

    return [add, remove, update, review]


def api_payload(add, remove, update):
    """Returns a list of strings with " escaped for each club changes,
    needed for API call.

        Args:
            all_diff = return from diff() for each club

        Returns:
            list of strings with escaped "

        Raises:
            Does not raise an error, returns none if functions fails
    """
    if not add and not remove and not update:
        return None

    add_api = []
    remove_api = []
    update_api = []

    print(len(add))
    for item in add:
        print('add api')
        print(item)
        item_str = str(item)
        item_str.replace("'", "\"")
        add_api.extend(item_str)

    print(len(remove))
    for item in remove:
        print('remove api')
        print(item)
        item_str = str(item)
        item_str.replace("'", "\"")
        remove_api.extend(item_str)

    print(len(update))
    for item in update:
        print('update api')
        print(item)
        item_str = str(item)
        item_str.replace("'", "\"")
        update_api.extend(item_str)

    print('all api')

    print(add_api, remove_api, update_api)
    return [add_api, remove_api, update_api]


def id_compare_update(results, club_number):
    """Returns a ID for each host.
    This function returns a generated ID after it compares it to ID's
    on baseline, to avoid duplicate IDs.

        Args:
            results = list of results
            club_number = numerical value for club

        Returns:
            ID - generated ID

        Raises:
            Does not raise an error. If the ID does not contain all
            needed information, it will return base values for result_id.
    """
    last_results = results[-1]
    # open baseline json to compare to prior scans
    baseline = load_baseline(results)
    # last results updated_id = 'club_number' + 'length of results'
    result_id = (str(club_number) + str(len(results)))
    if baseline is None:
        return result_id

    if club_number is None:
        result_id = ''.join(last_results['IP'].split('.'))
        return result_id

    # add all baseline IDs to list
    baseline_ids = [int(item['ID']) for item in baseline]
    # add all results IDs to list
    results_ids = [int(item['ID']) for item in results]
    # get highest ID in list
    baseline_ids_max = max(baseline_ids)
    results_ids_max = max(results_ids)
    # returns dictionary item if ['ID'] matches result_id, None otherwise
    dict_item_id = next((item for item in baseline if item['ID'] ==
                         result_id), None)
    # returns dictionary item if ['Mac Address] matches mac in each item
    # returns none if the mac address is not found in item
    dict_item_mac = next((itm for itm in baseline if itm['Mac Address'] ==
                          results[-1]['Mac Address']), None)
    # if ID is found in baseline
    if dict_item_id is not None:
        # if mac address does not match mac address in item found
        if last_results['Mac Address'] != dict_item_id['Mac Address']:
            # if mac address is not found anywhere else in baseline
            if dict_item_mac is None:
                # create a new id
                result_id = str(club_number) + str(len(baseline) + 1)
                # make sure id created is not in baseline
                if results_ids_max > baseline_ids_max:
                    baseline_ids_max = results_ids_max
                while int(result_id) <= baseline_ids_max:
                    result_id = str(int(result_id) + 1)

                print('New Device found, adding to baseline {} '
                      .format(result_id))
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
            result_id = club_number + str(len(baseline) + 1)
            # make sure id created is not in baseline
            if results_ids_max > baseline_ids_max:
                baseline_ids_max = results_ids_max
            while int(result_id) <= baseline_ids_max:
                result_id = str(int(result_id) + 1)

            print('New Device found, adding to baseline {} '.format(result_id))
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
    if len(results) != 0:
        club = results[0]['Location']
    else:
        return None

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
            if today.strftime("%m-%d-%Y") in last_baseline:
                if len(list_dir) >= 2:
                    last_baseline = sorted_list_dir[-2]
                else:
                    return None
            # full path of baseline to use for difference
            baseline_path = path.join(club_bsln_path, str(last_baseline))
        elif len(list_dir) == 1:
            baseline_path = path.join(club_bsln_path, str(list_dir[0]))
        else:
            return None

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
                    # send command to get hostname
                    club_info = conn.send_command('sh run | inc hostname')
                    # search club pattern 'club000' in club_info
                    club_result = club_rgx.search(club_info)
                    print('Getting club ID... attempt', attempt + 1)
                    # if club pattern is not found
                    if club_result is None:
                        # search for regional pattern
                        club_result = reg_rgx.search(club_info)
                    # if regional pattern found
                    if club_result is not None:
                        # club_result returns reg pattern 'reg-000'
                        club_result = club_result.group(0)
                    # if reg pattern is not found
                    if club_result is None:
                        # look for ID in router hostname
                        raise OSError

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
                            return None
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
    if club_result is None:
        return None

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
            club_number = club_result
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

    if club_number is not None:
        # club_number is the return from club_num()
        asset1 = club_number
    else:
        if club_result is not None:
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
ip_list = ['10.6.3.0/24', '10.11.139.0/24', '10.16.11.0/24', '10.96.0.0/24']
ip_list = ['10.10.238.0/24']
main(ip_list)

end = time()
runtime = end - start
runtime = str(timedelta(seconds=int(runtime)))
print('\nScript Runtime: {} '.format(runtime))
