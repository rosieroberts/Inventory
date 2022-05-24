# This program scans the network to get an inventory of all assets
# from all clubs.


# !/usr/bin/env python3

from os import path, listdir
from sys import exit
from json import dumps, load, decoder
from csv import DictWriter
from pathlib import Path
from time import time, ctime
from re import compile, IGNORECASE
from copy import deepcopy
from datetime import timedelta, date, datetime
from pprint import pformat
from ipaddress import ip_address, ip_network
import requests
import urllib3
import pymongo
from logging import (
    FileHandler,
    Formatter,
    StreamHandler,
    getLogger,
    DEBUG)
from argparse import ArgumentParser
import concurrent.futures
from nmap import PortScanner
from paramiko.ssh_exception import SSHException
from paramiko.buffered_pipe import PipeTimeout
from netmiko import ConnectHandler
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException)
from lib import ips
from lib.get_snipe_inv import get_loc_id, get_snipe
from lib import config as cfg
from lib import inv_mail as mail


start = time()
today = date.today()
not_connected = []
not_scanned = []
clubs = []
additional_ids = []
restored = []
added = []
updated = []
deleted = []
scan_count = 0
scan_queue = []
club_queue = []
api_status = []

# list of location IDs from snipeIT
location_ids = get_loc_id()

# logging set up
logger = getLogger(__name__)

file_formatter = Formatter('{asctime} {threadName}: {message}', style='{')
stream_formatter = Formatter('{threadName} {message}', style='{')

# logfile
file_handler = FileHandler('/opt/Inventory/logs/asset_inventory{}.log'
                           .format(today.strftime('%m%d%Y')))
file_handler.setLevel(DEBUG)
file_handler.setFormatter(file_formatter)

# console
stream_handler = StreamHandler()
stream_handler.setFormatter(stream_formatter)
stream_handler.setLevel(DEBUG)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)


def main(ip_list):
    """main function to run script, scans all clubs using
    get_ip_list from ips.py or using a specific list of ips from args

    Args:
        ip_list

    Returns:
        None

    Raises:
        Does not raise an error.
    """
    print(cfg.intro1)
    print(cfg.intro2)
    get_snipe()
    csv_trunc()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            threads = [executor.submit(club_scan, ip) for ip in ip_list]
        script_info()
        get_snipe()
    except(OSError, KeyboardInterrupt):
        logger.exception('Script Error')
        threads = None
        script_info()

    return threads


def club_scan(ip):
    """function to scan each club using club ip

    Args:
        ip for each location

    Returns:
        Info for assets that need to be added, removed or updated

    Raises:
        Does not raise an error.
        Returns None if club cannot be scanned
    """

    all_diff = []
    all_api_payload = []
    add = []
    remove = []
    connect_obj = None
    global scan_count

    ip_regex = compile(r'(?:\d+\.){3}\d+')

    ip_address = ip_regex.search(ip)
    clb_runtime_str = time()

    if ip_address:
        # connect to router and get connect object
        router_connect = connect(str(ip))
    try:
        if router_connect:
            connect_obj = router_connect
            if ip_address:

                results = get_router_info(connect_obj,
                                          str(ip),
                                          location_ids)
            else:
                results = None

            for item in results:
                item['ID'] = get_id(item['Asset Tag'], item['Mac Address'])
            results_copy = deepcopy(results)

            all_diff = diff(results_copy)
            if all_diff:
                all_api_payload = api_payload(all_diff)
                if all_api_payload:
                    add = all_api_payload[0]
                    remove = all_api_payload[1]
                    restore = all_api_payload[2]
                    update = all_api_payload[3]
                api_call(results_copy[0]['Location'], add, remove, restore, update)
            logger.info('{} scanned successfully'.format(results[0]['Location']))
            updated_results = save_results(results, str(ip))
            add_to_db(updated_results, scan_count)
            csv(results, scan_count)
            scan_started()
            connect_obj.disconnect()
            logger.info('disconnected from {}'.format(results[0]['Location']))
            if scan_queue:
                scan_queue.remove(ip)
            clubs.append(results[0]['Location'])

    except(urllib3.exceptions.ProtocolError):
        logger.critical('Remote end closed connection without response', exc_info=True)
        logger.debug('Scanning next club....')
    except(TypeError):
        logger.critical('Scan for {} ended abruptly'.format(results[0]['Location']), exc_info=True)
        logger.debug('Scanning next club....')

    clb_runtime_end = time()
    clb_runtime = clb_runtime_end - clb_runtime_str
    clb_runtime = str(timedelta(seconds=int(clb_runtime)))

    if router_connect:
        if results:
            logger.info('{} Scan Runtime: {} '
                        .format(results[0]['Location'], clb_runtime))
    else:
        logger.info('Club Scan Runtime: {} '.format(clb_runtime))
    return results_copy


def scan_started():
    global scan_count
    scan_count += 1
    return scan_count


def connect(ip):
    """Connects to router using .1 address from each ip router from ip_list.

    Returns:
        Netmiko connection object.

    Raises:
        Does not raise an error. If connection is unsuccessful,
        None is returned.
    """
    club = get_club(ip)
    if club:
        logger.info('Scanning {}'.format(club))
    else:
        logger.info('Scanning {}'.format(ip))
    for _ in range(1):
        for attempt in range(2):
            startconn = time()
            try:
                logger.debug('Connecting...')

                net_connect = ConnectHandler(device_type='fortinet',
                                             host=ip,
                                             username=cfg.ssh['username'],
                                             password=cfg.ssh['password'],
                                             blocking_timeout=20)

                endconn = time()
                time_elapsed = endconn - startconn
                logger.debug('Connection achieved in {} seconds'
                             .format(int(time_elapsed)))

                return net_connect

            except(NetMikoTimeoutException,
                   NetMikoAuthenticationException,
                   SSHException,
                   OSError,
                   ValueError,
                   EOFError):
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
                            logger.debug('port 22 is showing closed for {}'
                                         .format(ip))
                            not_connected.append(ip)
                            return None
                        else:
                            logger.debug('Port 22 is open ')
                            break
                    else:
                        logger.debug('port 22 is closed for {}'
                                     .format(ip))
                        continue
                if attempt == 0:
                    logger.debug('error connecting, trying to connect to {} again '.format(ip))

                else:
                    logger.error('Could not connect to host', exc_info=True)

        # exhausted all tries to connect, return None and exit
        logger.error('Connection to {} is not possible: '.format(ip))
        not_connected.append(ip)
        return None


def get_router_info(conn, host, loc_id_data):
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
    mac_regex = compile(cfg.mac_rgx)
    ip_regex = compile(cfg.ip_rgx)
    fortext_regex = compile(cfg.fortext)
    not_added = []
    ip_ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

    for _ in range(1):
        for attempt2 in range(2):
            if conn is not None:
                try:
                    host_ip_type = ip_regex.search(host)
                    if host_ip_type:
                        arp_table = conn.send_command('get system arp')

                    arp_list = arp_table.splitlines()
                    arp_list_upd = []

                    # Remove IPs not within ip_ranges
                    for item in arp_list:
                        ip_result = ip_regex.search(item)
                        if ip_result is not None:
                            ip_result = ip_result.group(0)
                            ip_add = ip_address(ip_result)
                            for ip_range in ip_ranges:
                                if ip_add in ip_network(ip_range):
                                    arp_list_upd.append(item)

                    # ARP table does not include main router mac, adding to list of devices
                    mac_addr_inf = conn.send_command('get hardware nic wan1 | grep Permanent_HWaddr')
                    router_info = (str(host) + ' ' + str(mac_addr_inf))
                    arp_list_upd.insert(0, router_info)

                    for item in arp_list_upd:
                        ip_result = ip_regex.search(item)
                        mac_result = mac_regex.search(item)
                        fortext_result = fortext_regex.search(item)
                        if ip_result is not None and mac_result is not None:
                            ip_result = ip_result.group(0)
                            mac_result = mac_result.group(0)
                            if fortext_result is not None:
                                fortext_result = fortext_result.group(0)
                            mac_result = cfg.mac_address_format(mac_result)
                            vendor = cfg.get_oui_vendor(mac_result)
                            device_type = cfg.get_device_type(
                                ip_result,
                                club_result,
                                vendor
                            )
                            octets = ip_result.split('.')
                            first_octet = int(octets[0])
                            sec_octet = int(octets[1])
                            hostname = get_hostnames(ip_result)
                            fortext = cfg.is_fortext(fortext_result)
                            if fortext is not None:
                                device_type = fortext
                                hostname = {'ip': ip_result,
                                            'status': 'up',
                                            'status ID': '6',
                                            'hostnames': ''}

                            model_name = cfg.model_name(device_type, vendor)
                            model_id = cfg.models.get(model_name)
                            club_number = club_num(club_result)
                            asset_tag = asset_tag_gen(
                                ip_result,
                                club_number,
                                club_result,
                                mac_result,
                                vendor
                            )
                            tag_exists = check_tag(asset_tag, mac_result)
                            if tag_exists is True:
                                asset_tag = str(asset_tag) + '0'
                            if hostname is None:
                                continue
                            loc_id = 'null'
                            try:
                                if loc_id_data.get('total') != 0:
                                    for itm in loc_id_data['rows']:
                                        if itm['name'] == str(club_result):
                                            loc_id = str(itm['id'])

                            except KeyError:
                                logger.critical('No loc_id', exc_info=True)
                                loc_id = None
                                loc_id = str(loc_id)

                            # for main results
                            host_info = {
                                'ID': None,
                                'Asset Tag': asset_tag,
                                'IP': ip_result,
                                'Location': club_result,
                                'Location ID': loc_id,
                                'Category': device_type,
                                'Manufacturer': vendor,
                                'Model Name': model_name,
                                'Model Number': model_id,
                                'Hostname': hostname['hostnames'],
                                'Mac Address': mac_result,
                                'Status': hostname['status'],
                                'Status ID': hostname['status ID']}

                            # The first value added to 'results'
                            # is the router value. This is only added if the
                            # host IP is 172.31.x.x.
                            # Subsequently, the rest of the mac values
                            # are compared to the first value.
                            # If the mac address is the same,
                            # values are not written to 'results' to avoid
                            # duplicate values from final list.
                            if len(results) == 0:
                                if first_octet == 172 and sec_octet == 31:
                                    results.append(host_info)
                            else:
                                if (host_info['Mac Address'] !=
                                        results[0]['Mac Address']):
                                    results.append(host_info)
                                else:
                                    not_added.append(host_info)
                                    continue
                            # compare ID to inventory in snipe-it and update ID if found
                            updated_id = get_id(asset_tag, mac_result)
                            if updated_id is not None:
                                results[-1]['ID'] = updated_id

                    # when the first value in sh arp is not 10.x.x.1 items
                    # are added to not_added list until it finds the router.
                    # Then, not_added items mac's are compared to router
                    # mac's, and if different, added to results to avoid
                    # duplicate values
                    if not_added:
                        for itm in not_added:
                            if len(results) == 0:
                                results.append(itm)
                            else:
                                if itm['Mac Address'] != results[0]['Mac Address']:
                                    results.append(itm)
                                    # compare ID to inventory in snipe-it and update ID if found
                                    updated_id = get_id(asset_tag, mac_result)

                                    if updated_id is not None:
                                        results[-1]['ID'] = updated_id

                    # make directory that will contain all full scans by date
                    full_scan_dir = path.join('/opt/Inventory/scans/full_scans')
                    full_scan_dir_obj = Path(full_scan_dir)
                    full_scan_dir_obj.mkdir(parents=True, exist_ok=True)

                    if results:
                        logger.debug('Results complete...')
                        logger.debug('Writing {} results to files...'
                                     .format(results[0]['Location']))
                        # writing full scan to .json
                        club_output = open(
                            '/opt/Inventory/scans/full_scans/full_scan{}.json'.format(
                                today.strftime('%m%d%Y')), 'a+')

                        for item in results:
                            club_output.write(dumps(item, indent=4))
                        club_output.close()
                    break

                except(OSError,
                       PipeTimeout):

                    if attempt2 == 0:
                        logger.error('Could not connect to router, trying again', exc_info=True)
                        continue
                    else:
                        logger.critical('Could not get arp table for ip {}'
                                        .format(host), exc_info=True)
                        not_connected.append(host)
                        failed_results = {'Host': host,
                                          'Location': club_result,
                                          'Status': 'could not get arp table'}
                        f_results.append(failed_results)  # for debugging

    end2 = time()
    runtime2 = end2 - start2
    logger.debug('Club devices information was received in {}'
                 .format(runtime2))
    logger.debug(pformat(results))
    return results


def save_results(results, host):
    """Function to add results to .json and .csv files

    Args:
        results - list returned from get_router_info() for each location

    Returns:
        Function writes to files and updates results with ID from SnipeIT

    Raises:
        Does not raise an error. File is created when function is called and
        if file already exists, results list is appended to
        end of existing file.
    """

    if results:

        # make directory that will contain individual scans by club
        if results[0]['Location'] is not None:
            mydir = path.join('/opt/Inventory/scans/baselines/{}'.format(results[0]['Location']))
        else:
            mydir = path.join('/opt/Inventory/scans/baselines/{}'.format(results[0]['IP']))

        mydir_obj = Path(mydir)
        mydir_obj.mkdir(parents=True, exist_ok=True)
        club_base_file = open(
            mydir + '/{}_{}.json'.format(results[0]['Location'],
                                         today.strftime('%m%d%Y')), 'w+')

        for item in results:
            if item['ID'] is None:
                item_id = get_id(item['Asset Tag'], item['Mac Address'])
                if item_id:
                    item['ID'] = item_id
                else:
                    continue

        logger.debug('Updated new entries in mongodb with IDs from snipe-IT')
        # dump .json file for each raw club scan in directory
        club_base_file.write(dumps(results, indent=4))
        club_base_file.close()
        return results

    else:
        logger.error('No results received from router')
        not_connected.append(host)


def add_to_db(results, db_count):
    """ add scan to mongoDB """

    client = pymongo.MongoClient("mongodb://localhost:27017/")

    # Use database called inventory
    db = client['inventory']

    # use collection named by date of scan
    today_date = today.strftime('%m%d%Y')
    collection_name = 'scan_' + today_date
    scan_col = db[collection_name]

    # delete prior scan items
    if db_count == 0:
        if scan_col.count() > 0:
            scan_col.delete_many({})

    # insert full scan into mongodb collection
    scan_col.insert_many(results)


def csv(results, scan_count):
    """ Write results to csv"""

    if results:
        keys = results[0].keys()
        for item in results:
            item.pop('ID')
            item.pop('Status ID')
            item.pop('Location ID')
            item.pop('_id')

        # create .csv file with full scan
        with open('/opt/Inventory/scans/full_scans/full_scan{}.csv'
                  .format(today.strftime('%m%d%Y')), 'a') as csvfile:
            csvwriter = DictWriter(csvfile, keys)
            if scan_count == 0:
                csvwriter.writeheader()
            csvwriter.writerows(results)
            logger.debug('results written to .csv file')
    else:
        logger.error('No results written to .csv file')


def csv_trunc():
    # truncating csv file if it was ran a prior time on same day to
    # avoid duplicate values

    full_csv = ('/opt/Inventory/scans/full_scans/full_scan{}.csv'
                .format(today.strftime('%m%d%Y')))
    if (path.exists(full_csv) and path.isfile(full_csv)):
        f = open(full_csv, "w+")
        f.close()


def check_if_remove(diff_item):
    """ Check if record has not been in baseline for last 4 scans (weeks)"""
    baselines = last_4_baselines(diff_item)

    if baselines is None:
        return False

    baseline_1 = baselines[0]
    baseline_2 = baselines[1]
    baseline_3 = baselines[2]
    baseline_4 = baselines[3]

    id_found = next((itm for itm in baseline_1 if
                     diff_item['ID'] == itm['ID']), None)

    mac_found = next((item for item in baseline_1 if
                      diff_item['Mac Address'] ==
                      item['Mac Address']), None)

    if id_found is not None and mac_found is not None:
        return False

    id_found_2 = next((itm for itm in baseline_2 if
                       diff_item['ID'] == itm['ID']), None)

    mac_found_2 = next((item for item in baseline_2 if
                        diff_item['Mac Address'] ==
                        item['Mac Address']), None)
    if id_found_2 is not None and mac_found_2 is not None:
        return False

    id_found_3 = next((itm for itm in baseline_3 if
                       diff_item['ID'] == itm['ID']), None)

    mac_found_3 = next((item for item in baseline_3 if
                        diff_item['Mac Address'] ==
                        item['Mac Address']), None)

    if id_found_3 is not None and mac_found_3 is not None:
        return False

    id_found_4 = next((itm for itm in baseline_4 if
                       diff_item['ID'] == itm['ID']), None)

    mac_found_4 = next((item for item in baseline_4 if
                        diff_item['Mac Address'] ==
                        item['Mac Address']), None)
    if id_found_4 is not None and mac_found_4 is not None:
        return False

    else:
        return True


def diff(results):
    """ Function to get differences between current and prior scans
    by date of scan.
    Function returns a list of all differences.

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

    if results:
        logger.debug('Comparing to Prior Scan, Looking for Differences')
        club = results[0]['Location']
    else:
        return None
    add = []
    remove = []
    update = []
    restore = []
    all_diff = []
    results_macs = []

    client = pymongo.MongoClient("mongodb://localhost:27017/")

    # Use database called inventory
    db = client['inventory']

    # Use database "snipe" to compare
    snipe_coll = db['snipe']
    # all deleted items in snipe
    deleted_coll = db['deleted']

    # Find out if location has already been scanned
    snipe_location = snipe_coll.find_one({'Location': results[0]['Location']},
                                         {'Location': 1, '_id': 0})

    # If location is not found,
    if not snipe_location:
        logger.debug('No prior scan found to compare, adding all items to snipe-it')
        # add all items
        for item in results:
            add.append(item)
           
        if add:
            logger.debug('Adding devices to Scan Files')
            # make directory that will contain all scan statuses by date
            mydir = path.join('/opt/Inventory/scans/scan_status')
            mydir_obj = Path(mydir)
            mydir_obj.mkdir(parents=True, exist_ok=True)

            # create file for add
            add_file = open(mydir + '/add_{}.json'
                            .format(today.strftime("%m%d%Y")), 'a+')
            add_file.write(dumps(list(add), indent=4))
            add_file.close()
            all_diff.extend(add)
            return [add, remove, restore, update]
        else:
            return None

    if results[0]['Location'] != snipe_location['Location']:
        logger.debug('Club information cannot be compared')
        return None

    # make directory that will contain all scan statuses by date
    mydir = path.join('/opt/Inventory/scans/scan_status')
    mydir_obj = Path(mydir)
    mydir_obj.mkdir(parents=True, exist_ok=True)

    # create file to write status of differences as they happen
    status_file = open('/opt/Inventory/scans/scan_status/scan_{}'
                       .format(today.strftime('%m%d%Y')), 'a+')

    if club:
        status_file.write('\n\n')
        status_file.write(club.upper())
        status_file.write('\n')

    count_add = 0
    count_remove = 0
    count_restore = 0
    count_update = 0

    # Query mongo for all mac addresses in current location
    # location is based on results[0]['Location']
    club_mac = snipe_coll.find({'Location': results[0]['Location']},
                               {'Mac Address': 1, '_id': 0})
    # add db query to a list of dictionaries
    club_mac = list(club_mac)

    # list comprehension to get mac address values from snipe db
    # from list of dictionaries to just a list of mac addresses
    club_mac_list = [item['Mac Address'] for item in club_mac]

    for item in results:
        try:
            # find mac address in deleted list, to see whether or not item is new or
            # is being restored
            deleted_mac = deleted_coll.find_one({'_snipeit_mac_address_7': item['Mac Address'],
                                                'Location': item['Location']},
                                                {'_snipeit_mac_address_7': 1, '_id': 0})

            results_macs.append(item['Mac Address'])
            # query for specific mac address from results in mongodb
            mac_in_snipe = snipe_coll.find({'Mac Address': item['Mac Address'],
                                            'Location': item['Location'],
                                            'IP': item['IP']},
                                           {'Mac Address': 1, 'Asset Tag': 1, '_id': 0})

            asset_tag_diff = snipe_coll.find({'Mac Address': item['Mac Address'],
                                              'Location': item['Location'],
                                              'IP': item['IP'], 'Asset Tag': item['Asset Tag']},
                                             {'Mac Address': 1, 'Asset Tag': 1, '_id': 0})

            hostname_diff = snipe_coll.find({'Mac Address': item['Mac Address'],
                                             'Location': item['Location'],
                                             'IP': item['IP'],
                                             'Hostname': item['Hostname']},
                                            {'Mac Address': 1, 'Asset Tag': 1, '_id': 0})

            mac_in_snipe = list(mac_in_snipe)
            asset_tag_diff = list(asset_tag_diff)
            hostname_diff = list(hostname_diff)

            # see if mac is in other locations
            if not mac_in_snipe:
                # mac address found in a different location
                mac_other_snipe = snipe_coll.find({'Mac Address': item['Mac Address']},
                                                  {'Mac Address': 1, 'Location': 1, '_id': 0})
                # mac address found with a different IP
                mac_ip_snipe = snipe_coll.find({'Mac Address': item['Mac Address'],
                                                'Location': item['Location']},
                                               {'Mac Address': 1, 'IP': 1, '_id': 0})
                mac_other_snipe = list(mac_other_snipe)
                mac_ip_snipe = list(mac_ip_snipe)
                if mac_other_snipe and not mac_ip_snipe:
                    count_update += 1
                    update.append(item)
                    msg1 = ('Device from {}, ID {} and Mac Address {} '
                            'has a different location - {}\n'
                            .format(mac_other_snipe[0]['Location'],
                                    item['ID'],
                                    item['Mac Address'],
                                    item['Location']))
                    logger.debug('UPDATED ASSET {}'.format(count_update))
                    logger.debug(msg1)
                    status_file.write(msg1)

                elif not mac_in_snipe and mac_ip_snipe:
                    count_update += 1
                    update.append(item)
                    msg1 = ('Device from {}, ID {} and Mac Address {} '
                            'has a different IP - {}\n'
                            .format(item['Location'],
                                    item['ID'],
                                    item['Mac Address'],
                                    mac_ip_snipe[0]['IP']))
                    logger.debug('UPDATED ASSET {}'.format(count_update))
                    logger.debug(msg1)
                    status_file.write(msg1)

                elif not mac_in_snipe and not mac_other_snipe and not deleted_mac:
                    count_add += 1

                    add.append(item)
                    msg1 = ('New device with ID {} and Mac Address {} '
                            'added\n'
                            .format(item['ID'],
                                    item['Mac Address']))
                    logger.debug('NEW ASSET {}'.format(count_add))
                    logger.debug(msg1)
                    status_file.write(msg1)

                elif not mac_in_snipe and deleted_mac:
                    count_restore += 1
                    restore.append(item)
                    msg1 = ('Device with ID {} and Mac Address {} '
                            'restored\n'
                            .format(item['ID'],
                                    item['Mac Address']))
                    logger.debug('RESTORED ASSET {}'.format(count_restore))
                    logger.debug(msg1)
                    status_file.write(msg1)

            elif mac_in_snipe and not asset_tag_diff:
                count_update += 1
                update.append(item)
                msg1 = ('Device from {}, ID {} and Mac Address {} '
                        'has a different Asset Tag - {}\n'
                        .format(item['Location'],
                                item['ID'],
                                item['Mac Address'],
                                mac_in_snipe[0]['Asset Tag']))
                logger.debug('UPDATED ASSET {}'.format(count_update))
                logger.debug(msg1)
                status_file.write(msg1)

            elif mac_in_snipe and not hostname_diff:
                count_update += 1
                update.append(item)
                msg1 = ('Device from {}, ID {} and Mac Address {} '
                        'has a different Hostname - {}\n'
                        .format(item['Location'],
                                item['ID'],
                                item['Mac Address'],
                                item['Hostname']))
                logger.debug('UPDATED ASSET {}'.format(count_update))
                logger.debug(msg1)
                status_file.write(msg1)

            else:
                continue

        except (TypeError, IndexError):
            logger.error('Cannot find differences for {} '
                         .format(item), exc_info=True)

    # check if each mac address in snipedb is in results mac address list
    not_in_results = list(filter(lambda item: item not in results_macs, club_mac_list))

    if not_in_results:
        for item in not_in_results:

            try:
                itm = snipe_coll.find({'Mac Address': item},
                                      {'_id': 0})
                itm = list(itm)
                itm = itm[0]
                itm['ID'] = str(itm['ID'])
                check_remove = check_if_remove(itm)
                # if check_remove is true, remove device from snipeit
                if check_remove is True:
                    count_remove += 1
                    remove.append(itm)
                    msg7 = ('Device with ID {} and Mac Address {} '
                            'no longer found, '
                            'will be removed '
                            .format(itm['ID'],
                                    itm['Mac Address']))
                    logger.debug('REMOVED ASSET {}'.format(count_remove))
                    logger.debug(msg7)
                    status_file.write(msg7)
            except (KeyError):
                logger.error('Cannot remove device with Mac Address {} '
                             .format(item), exc_info=True)

    if add or restore:

        add_file = open(mydir + '/add_{}.json'
                        .format(today.strftime("%m%d%Y")), 'a+')
        add_file.write(dumps(list(add), indent=4))
        add_file.write(dumps(list(restore), indent=4))
        add_file.close()
        all_diff.extend(add)

    if remove:
        # create file for remove
        remove_file = open(mydir + '/remove_{}.json'
                           .format(today.strftime("%m%d%Y")), 'a+')
        remove_file.write(dumps(list(remove), indent=4))
        remove_file.close()
        all_diff.extend(remove)

    if add or remove or restore or update:
        logger.info('Differences found, will update snipe-it')
    else:
        logger.info('_____No differences found____')

    return [add, remove, restore, update]


def api_call(club_id, add, remove, restore, update):

    # make directory that will contain all scan statuses by date
    mydir = path.join('/opt/Inventory/scans/api_status')
    mydir_obj = Path(mydir)
    mydir_obj.mkdir(parents=True, exist_ok=True)

    # create file to write status of differences as they happen
    status_file = open('/opt/Inventory/scans/api_status/scan_{}'
                       .format(today.strftime('%m%d%Y')), 'a+')
    if club_id:
        club = str(club_id)

        if club and add or remove or restore or update:
            status_file.write('\n\n')
            status_file.write(club.upper())
            status_file.write('\n')

    # looking for id in mongo "deleted" collection
    client = pymongo.MongoClient("mongodb://localhost:27017/")

    # Use database called inventory
    db = client['inventory']

    # Use database "deleted"
    del_coll = db['deleted']

    # use database 'snipe'
    snipe_coll = db['snipe']

    if add:
        for item in add:
            asset_tag = item['asset_tag']
            # checking if item is already in snipe_it to prevent duplicates
            try:
                url = cfg.api_url_get + str(asset_tag)

                response = requests.request("GET", url=url, headers=cfg.api_headers)

                logger.info('Request GET - Add')
                content = response.json()
                status_a = str(content['status'])
                # record status of api call and save with tag in list
                tag = str(content['asset_tag'])
                if tag:
                    status_file.write('Cannot add item, asset_tag {} already exists '
                                      'in Snipe-IT, review item\n{}'
                                      .format(item['asset_tag'], item))
            except (KeyError,
                    decoder.JSONDecodeError):
                tag = None
            if tag is not None:
                logger.error('Cannot add item to Snipe-IT, asset tag {} already exists.'
                             .format(item['asset_tag']), exc_info=True)
                continue

            try:
                logger.debug('Creating new item')
                # adding brand new item to snipe-it
                item_id = None
                url = cfg.api_url
                item_str = str(item)
                payload = item_str.replace('\'', '\"')
                logger.debug(pformat(payload))
                response = requests.request("POST",
                                            url=url,
                                            data=payload,
                                            headers=cfg.api_headers)
                logger.info('Request POST - Add')
                logger.info(pformat(response.text))
                content = response.json()
                status_a = str(content['status'])
                # record status of api call and save with tag in list
                api_snipe = {'asset_tag': asset_tag,
                             'status': status_a}

                if response.status_code == 200:
                    if status_a == 'success':
                        msg_add = ('Added new item '
                                   'with asset-tag {} to Snipe-IT\n')
                        status_file.write(msg_add.format(item['asset_tag']))
                        logger.info(msg_add.format(item['asset_tag']))
                        add_tuple = (club_id, item['asset_tag'])
                        added.append(add_tuple)
                        api_status.append(api_snipe)

                elif response.status_code == 401:
                    status_file.write('Unauthorized. Could not send '
                                      'request to add new item '
                                      'with asset-tag {} to Snipe-IT\n'
                                      .format(item['asset_tag']))
                    api_status.append(api_snipe)
                elif response.status_code == 422:
                    status_file.write('Payload does not match Snipe_IT. '
                                      'item {}\n'
                                      .format(item['asset_tag']))
                    api_status.append(api_snipe)

                else:
                    api_snipe = {'asset_tag': asset_tag,
                                 'status': status_a}
                    api_status.append(api_snipe)
                    msg_add = ('Could not add new item '
                               'with asset-tag {} to Snipe-IT, review.\n')
                    status_file.write(msg_add.format(item['asset_tag']))
                    logger.info(msg_add.format(item['asset_tag']))

            except (KeyError,
                    decoder.JSONDecodeError):
                logger.error('There was an error adding the asset '
                             'to Snipe-IT, check: '
                             '{}, ip {}, mac address {}'
                             .format(item['Location'],
                                     item['_snipeit_ip_6'],
                                     item['_snipeit_mac_address_7']), exc_info=True)

    if restore:
        for item in restore:

            # find previously deleted item by mac address, and ip
            del_item = del_coll.find_one({'_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                          '_snipeit_ip_6': item['_snipeit_ip_6'],
                                          'Location': item['Location']},
                                         {'id': 1, 'asset_tag': 1, '_snipeit_mac_address_7': 1,
                                          '_snipeit_ip_6': 1, '_id': 0})

            # if not found, make sure item with just the mac address was not previously deleted
            # ip has changed, update deleted collection in mongo with new ip
            del_item_diff_ip = del_coll.find_one({'_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                                  'Location': item['Location']},
                                                 {'id': 1, 'asset_tag': 1, '_snipeit_mac_address_7': 1,
                                                  '_snipeit_ip_6': 1, '_id': 0})

            del_item_host = del_coll.find_one({'_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                               '_snipeit_ip_6': item['_snipeit_ip_6'],
                                               'Location': item['Location'],
                                               '_snipeit_hostname_8': item['_snipeit_hostname_8']},
                                              {'id': 1, 'asset_tag': 1, '_snipeit_mac_address_7': 1,
                                               '_snipeit_ip_6': 1, '_id': 0})

            try:
                if del_item:
                    item_tag = str(del_item['asset_tag'])
                    item_id = str(del_item['id'])
                    item_ip = str(del_item['_snipeit_ip_6'])
                    item_host = str(item['_snipeit_hostname_8'])

                    # all is needed to restore is asset_tag
                    url = cfg.api_url_restore_deleted.format(item_id)
                    response = requests.request("POST",
                                                url=url,
                                                headers=cfg.api_headers)
                    logger.info('Request POST - Restore 1')

                    if not del_item_host:
                        # if item has a differet hostname, partially update item in snipe it
                        url = cfg.api_url_update.format(del_item_diff_ip['id'])
                        item_str = str({'_snipeit_ip_6': item['_snipeit_ip_6'],
                                        '_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                        '_snipeit_hostname_8': item['_snipeit_hostname_8']})
                        payload = item_str.replace('\'', '\"')
                        logger.debug(payload)
                        response2 = requests.request("PATCH",
                                                     url=url,
                                                     data=payload,
                                                     headers=cfg.api_headers)
                        logger.info('Request PATCH - Restore 2')
                        logger.debug(pformat(response2.text))
                        content2 = response2.json()
                        status_r_2 = str(content2['status'])
                        # record status of api call and save with tag in list
                        api_snipe = {'asset_tag': item_tag,
                                     'status': status_r_2}
                        api_status.append(api_snipe)
                        msg = ('Updated item with asset_tag {} '
                               'and id {} with new hostname {} in Snipe-IT\n')

                        del_coll.update_one({'_snipeit_mac_address_7': item['_snipeit_mac_address_7']},
                                            {'$set': {'_snipeit_ip_6': item['_snipeit_ip_6'],
                                                      '_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                                      '_snipeit_hostname_8': item['_snipeit_hostname_8']}})

                        status_file.write(msg.format(item_tag, item_id, item_host))
                        logger.info(msg.format(item_tag, item_id, item_host))

                if del_item_diff_ip and not del_item:
                    item_tag = str(del_item_diff_ip['asset_tag'])
                    item_id = str(del_item_diff_ip['id'])
                    item_ip = str(item['_snipeit_ip_6'])

                    # all is needed to restore is asset_tag
                    url = cfg.api_url_restore_deleted.format(item_id)
                    response = requests.request("POST",
                                                url=url,
                                                headers=cfg.api_headers)
                    logger.info('Request POST - Restore 2')

                    # if item has a different ip address, partially update item in snipe it
                    url = cfg.api_url_update.format(del_item_diff_ip['id'])
                    item_str = str({'_snipeit_ip_6': item['_snipeit_ip_6'],
                                    '_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                    '_snipeit_hostname_8': item['_snipeit_hostname_8']})
                    payload = item_str.replace('\'', '\"')
                    logger.debug(payload)
                    response2 = requests.request("PATCH",
                                                 url=url,
                                                 data=payload,
                                                 headers=cfg.api_headers)
                    logger.info('Request PATCH - Restore 1')
                    logger.debug(pformat(response2.text))
                    content2 = response2.json()
                    status_r_2 = str(content2['status'])
                    # record status of api call and save with tag in list
                    api_snipe = {'asset_tag': item_tag,
                                 'status': status_r_2}
                    api_status.append(api_snipe)
                    msg = ('Updated item with asset_tag {} '
                           'and id {} with new IP {} in Snipe-IT\n')

                    del_coll.update_one({'_snipeit_mac_address_7': item['_snipeit_mac_address_7']},
                                        {'$set': {'_snipeit_ip_6': item['_snipeit_ip_6'],
                                                  '_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                                  '_snipeit_hostname_8': item['_snipeit_hostname_8']}})

                    status_file.write(msg.format(item_tag, item_id, item_ip))
                    logger.info(msg.format(item_tag, item_id, item_ip))
                logger.debug(pformat(response.text))
                content = response.json()
                status_r = str(content['status'])
                # record status of api call and save with tag in list
                api_snipe = {'asset_tag': item_tag,
                             'status': status_r}
                api_status.append(api_snipe)
                if response.status_code == 200:
                    if status_r == 'success':
                        msg_add = ('Restored item '
                                   'with asset-tag {} to Snipe-IT\n')
                        status_file.write(msg_add.format(item['asset_tag']))
                        logger.info(msg_add.format(item['asset_tag']))
                        res_tuple = (club_id, item_tag)
                        restored.append(res_tuple)
                    elif status_r == 'error':
                        msg_add = ('Could not add new item '
                                   'with asset-tag {} to Snipe-IT, review.\n')
                        status_file.write(msg_add.format(item['asset_tag']))
                        logger.info(msg_add.format(item['asset_tag']))

                elif response.status_code == 401:
                    status_file.write('Unauthorized. Could not send '
                                      'request to add new item '
                                      'with asset-tag {} to Snipe-IT\n'
                                      .format(item['asset_tag']))
                elif response.status_code == 422:
                    status_file.write('Payload does not match Snipe_IT. '
                                      'item {}\n'
                                      .format(item['asset_tag']))
            except (KeyError,
                    decoder.JSONDecodeError):
                logger.critical('There was an error adding the asset '
                                'to Snipe-IT, check: '
                                '{}, ip {}, mac address {}'
                                .format(item['Location'],
                                        item['_snipeit_ip_6'],
                                        item['_snipeit_mac_address_7']), exc_info=True)

    if update:
        for item in update:

            # get current snipe info for this mac address
            snipe_mac = snipe_coll.find({'Mac Address': item['_snipeit_mac_address_7']},
                                        {'Mac Address': 1, 'Asset Tag': 1,
                                         'IP': 1, 'Location': 1, 'Location ID': 1,
                                         'Hostname': 1, 'ID': 1, '_id': 0})

            try:
                snipe_mac = list(snipe_mac)

                url = cfg.api_url_update.format(snipe_mac[0]['ID'])
                item_str = str({'_snipeit_ip_6': item['_snipeit_ip_6'],
                                '_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                '_snipeit_hostname_8': item['_snipeit_hostname_8'],
                                'asset_tag': item['asset_tag'],
                                'rtd_location_id': item['rtd_location_id']})
                payload = item_str.replace('\'', '\"')
                logger.debug(payload)
                response = requests.request("PATCH",
                                            url=url,
                                            data=payload,
                                            headers=cfg.api_headers)
                logger.info('Request PATCH - Update 1')
                logger.debug(pformat(response.text))
                content = response.json()
                status_u = str(content['status'])
                # record status of api call and save with tag in list
                api_snipe = {'asset_tag': item['asset_tag'],
                             'status': status_u}

                if response.status_code == 200:
                    if status_u == 'success':
                        msg_upd = ('Updated item with asset_tag {} '
                                   'in Snipe-IT\n')
                        status_file.write(msg_upd.format(item['asset_tag']))
                        logger.info(msg_upd.format(item['asset_tag']))
                        upd_tuple = (item['Location'], item['asset_tag'])
                        updated.append(upd_tuple)
                        api_status.append(api_snipe)

                elif response.status_code == 422:
                    status_file.write('Payload does not match Snipe_IT. '
                                      'item {}\n'
                                      .format(item['asset_tag']))

                else:
                    api_snipe = {'asset_tag': asset_tag,
                                 'status': status_a}
                    api_status.append(api_snipe)
                    msg_upd = ('Could not update item '
                               'with asset-tag {} to Snipe-IT, review.\n')
                    status_file.write(msg_upd.format(item['asset_tag']))
                    logger.info(msg_upd.format(item['asset_tag']))

            except (KeyError,
                    decoder.JSONDecodeError):
                logger.critical('There was an error updating the asset '
                                'check result {}, ip {}, mac address {} '
                                'snipe item {}, ip {}, mac address {} '
                                .format(item['Location'],
                                        item['_snipeit_ip_6'],
                                        item['_snipeit_mac_address_7'],
                                        snipe_mac[0]['Location'],
                                        snipe_mac[0]['IP'],
                                        snipe_mac[0]['Mac Address']), exc_info=True)

    if remove:
        for item in remove:
            try:
                asset_tag = item['asset_tag']
                url = cfg.api_url + str(item['id'])
                response = requests.request("DELETE",
                                            url=url,
                                            headers=cfg.api_headers)
                logger.info('Request DELETE - Remove 1')
                logger.info(pformat(response.text))
                content = response.json()
                status_d = str(content['status'])

                if response.status_code == 200:
                    if status_d == 'success':
                        msg_rem = ('Removed item '
                                   'with asset-tag {} from Snipe-IT\n')
                        status_file.write(msg_rem.format(item['asset_tag']))
                        logger.info(msg_rem.format(item['asset_tag']))
                        # add remove item to mongo colletion -deleted
                        client = pymongo.MongoClient("mongodb://localhost:27017/")

                        # Use database called inventory
                        db = client['inventory']

                        # use collection named deleted
                        del_col = db['deleted']

                        del_item = del_col.find_one({'_snipeit_mac_address_7': item['_snipeit_mac_address_7'],
                                                     '_snipeit_ip_6': item['_snipeit_ip_6'],
                                                     'Location': item['Location']},
                                                    {'id': 1, 'asset_tag': 1, '_snipeit_mac_address_7': 1,
                                                     '_snipeit_ip_6': 1, '_id': 0})
                        if not del_item:
                            # add item to collection
                            del_col.insert_one(item)

                        del_tuple = (club_id, item['asset_tag'])
                        deleted.append(del_tuple)

                        # record status of api call and save with tag in list
                        api_snipe = {'asset_tag': asset_tag,
                                     'status': status_d}
                        api_status.append(api_snipe)

                elif response.status_code == 401:
                    msg_r = ('Unauthorized. Could not send '
                             'request to remove item '
                             'with asset-tag {} from Snipe-IT\n')

                    status_file.write(msg_r.format(item['asset_tag']))
                    logger.info(msg_r.format(item['asset_tag']))

                else:
                    api_snipe = {'asset_tag': asset_tag,
                                 'status': status_a}
                    api_status.append(api_snipe)
                    msg_rem = ('Could not remove item '
                               'with asset-tag {} to Snipe-IT, review.\n')
                    status_file.write(msg_rem.format(item['asset_tag']))
                    logger.info(msg_rem.format(item['asset_tag']))

            except (KeyError, decoder.JSONDecodeError):
                logger.error('There was an error removing the asset '
                             'check Asset Tag {}\n'
                             .format(item['Asset Tag']), exc_info=True)


def api_payload(all_diff):
    """Returns a list of strings with " escaped for each club changes,
    needed for API call.

        Args:
            all_diff = return from diff() for each club

        Returns:
            list of strings with escaped "

        Raises:
            Does not raise an error, returns none if functions fails
    """
    diff = deepcopy(all_diff)
    add = []
    remove = []
    restore = []
    update = []

    if not all_diff:
        return None

    # review = all_diff[3]

    for list in diff:
        for item in list:
            item['_snipeit_mac_address_7'] = item.pop('Mac Address')
            item['_snipeit_ip_6'] = item.pop('IP')
            item['_snipeit_hostname_8'] = item.pop('Hostname')
            item['asset_tag'] = item.pop('Asset Tag')
            item['id'] = item.pop('ID')
            if 'Model Number' in item:
                item['model_id'] = item.pop('Model Number')
            if 'Status ID' in item:
                item['status_id'] = item.pop('Status ID')
            if 'Location ID' in item:
                item['rtd_location_id'] = item.pop('Location ID')
            if 'Status' in item:
                item.pop('Status')

    add = diff[0]
    remove = diff[1]
    restore = diff[2]
    update = diff[3]

    for item in add:
        item.pop('id')

    for item in restore:
        item.pop('id')

    if add:
        logger.debug('ADD ASSETS FULL INFORMATION')
        logger.debug(pformat(add))
    if remove:
        logger.debug('REMOVE ASSETS FULL INFORMATION')
        logger.debug(pformat(remove))
    if restore:
        logger.debug('RESTORE ASSETS FULL INFORMATION')
        logger.debug(pformat(restore))
    return [add, remove, restore, update]


def get_id(asset_tag, mac_addr):
    """Returns a ID for each host.
    This function returns a generated ID after it compares it to ID's
    on baseline, to avoid duplicate IDs.
        Args:
            Asset Tag = asset tag of device
        Returns:
            ID - get ID from snipe-it
        Raises:
    """
    try:
        myclient = pymongo.MongoClient("mongodb://localhost:27017/")

        # use database named "inventory"
        mydb = myclient['inventory']

        # use collection named "snipe"
        snipe_coll = mydb['snipe']

        id_ = snipe_coll.find_one({'Asset Tag': asset_tag, 'Mac Address': mac_addr},
                                  {'ID': 1, '_id': 0})

        if id_:
            return id_['ID']

        else:
            asset_tag = asset_tag + '0'

            id_ = snipe_coll.find_one({'Asset Tag': asset_tag, 'Mac Address': mac_addr},
                                      {'ID': 1, '_id': 0})

            if id_:
                return id_['ID']

            else:
                return None

    except(KeyError):
        logger.error('Error getting ID for asset tag {}, and mac {} '.format(asset_tag, mac_addr), exc_info=True)
        return None


def check_tag(asset_tag, mac_addr):
    # Update
    """Returns a ID for each host.
    This function returns a generated ID after it compares it to ID's
    on baseline, to avoid duplicate IDs.

        Args:
            Asset Tag = asset tag of device

        Returns:
            ID - get ID from snipe-it

        Raises:

    """

    id_ = None
    try:
        myclient = pymongo.MongoClient("mongodb://localhost:27017/")

        # use database named "inventory"
        mydb = myclient['inventory']

        # use collection named "snipe"
        snipe_coll = mydb['snipe']

        id_ = snipe_coll.find_one({'Asset Tag': asset_tag, 'Mac Address': mac_addr},
                                  {'ID': 1, '_id': 0})
        id2_ = snipe_coll.find_one({'Asset Tag': asset_tag},
                                   {'ID': 1, '_id': 0})

        if id_ is not None:
            return False

        elif id_ is None and id2_ is not None:
            return True

        else:
            return False

    except (KeyError, IndexError):
        logger.critical('Could not check asset tag for {} '.format(mac_addr), exc_info=True)
        return False


def last_4_baselines(diff_item):
    """Opens and loads prior 4 scans as baselines for use in check_if_remove()

        Args:
            item from differences that no longer appears in results

        Returns:
            list of 4 baselines - list of dictionary items from baseline in prior 4 scans

        Raises:
            Does not raise an error. If there is no baseline, returns None
    """
    if diff_item:
        club = diff_item['Location']
    else:
        return None

    file_list = []

    try:
        club_bsln_path = '/opt/Inventory/scans/baselines/{}'.format(club)
        # get list of all files in club baseline directory
        list_dir = listdir(club_bsln_path)
        for item in list_dir:
            date_ = item[8:16]
            file_list.append(date_)
        if len(file_list) >= 4:
            # sort list to find latest 4 baselines
            file_list.sort(key=lambda date: datetime.strptime(date, '%m%d%Y'))
            bline_1 = club + '_' + file_list[-1] + '.json'
            bline_2 = club + '_' + file_list[-2] + '.json'
            bline_3 = club + '_' + file_list[-3] + '.json'
            bline_4 = club + '_' + file_list[-4] + '.json'

            # full path of baselines
            baseline_1_path = path.join(club_bsln_path, str(bline_1))
            baseline_2_path = path.join(club_bsln_path, str(bline_2))
            baseline_3_path = path.join(club_bsln_path, str(bline_3))
            baseline_4_path = path.join(club_bsln_path, str(bline_4))

        else:
            return None

        output_1 = open(baseline_1_path)
        baseline_1 = load(output_1)
        output_1.close()

        output_2 = open(baseline_2_path)
        baseline_2 = load(output_2)
        output_2.close()

        output_3 = open(baseline_3_path)
        baseline_3 = load(output_3)
        output_3.close()

        output_4 = open(baseline_4_path)
        baseline_4 = load(output_4)
        output_4.close()

        return baseline_1, baseline_2, baseline_3, baseline_4

    except(ValueError, FileNotFoundError, decoder.JSONDecodeError):
        logger.error('Cannot check baselines for diff item {} '
                     .format(diff_item), exc_info=True)

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

    fort_regex = compile(r'([0-9]{3}(?=-fgt-))', IGNORECASE)
    ip_regex = compile(r'(?:\d+\.){3}\d+')
    for _ in range(1):
        for attempt in range(2):
            if conn is not None:
                if ip_regex.search(host):
                    try:
                        club_info = conn.send_command('show system snmp sysinfo')
                        # search club number '000' in club_info
                        club_number = fort_regex.search(club_info)
                        club_result = None

                        if club_number is not None:
                            club_number = club_number.group(0)
                            club_result = 'club' + str(club_number)
                            break
                        # if pattern is not found
                        if club_result is None:
                            logger.critical('no club ID found')
                            # look for ID in router hostname
                            raise OSError

                    except(OSError,
                           NetMikoTimeoutException):
                        if attempt == 0:
                            logger.error('Could not send command. Trying again', exc_info=True)
                            continue
                        if attempt == 1:
                            logger.error('Getting club_id from nmap hostname', exc_info=True)
                            hostname = get_hostnames(host)
                            hostname_club = club_rgx.search(hostname['hostnames'])
                            if hostname_club:
                                club_result = hostname_club.group(0)
                            if not hostname_club:
                                logger.error('could not get club_id')
                                return None

                        if attempt > 0:
                            logger.error('could not get club_id', exc_info=True)
        club_result = str(club_result)
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
    try:
        hosts = str(ip)
        nmap_args = '-sn'
        scanner = PortScanner()
        scanner.scan(hosts=hosts, arguments=nmap_args)
        for ip in scanner.all_hosts():
            host = {'ip': ip}
            if 'hostnames' in scanner[ip]:
                hostname = scanner[ip].hostname()
                hostname = hostname.replace('.24hourfit.com', '')
                host['hostnames'] = hostname.upper()
            if 'status' in scanner[ip]:
                host['status'] = scanner[ip]['status']['state']
            if host['status'] == 'up':
                host['status ID'] = '6'
            if host['status'] == 'down':
                host['status ID'] = '8'
            return host

        return None

    except (KeyError):
        logger.error('problem getting hostname ', exc_info=True)
        return None


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
    # Extract club number for clubs
    club_id = club_n_regex.search(club_result)
    if club_id:
        # if club pattern is found
        club_id = club_id.group(0)
        club_number = club_id
    else:
        club_number = club_result

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

    if club_number:
        # club_number is the return from club_num()
        asset1 = club_number
    else:
        if club_result:
            # Extract location number
            club_id = loc_num_rgx.search(club_result)
            if club_id:
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


def get_club_ips(club):
    ''' Get ip address for club number in command line argument
    args: club in 'club000' format
    '''
    try:
        myclient = pymongo.MongoClient("mongodb://localhost:27017/")

        # use database named "inventory"
        mydb = myclient['inventory']

        # use collection 'club_list'
        club_list = mydb['club_list']

        # query IP
        ip = club_list.find_one({'Location': club}, {'IP': 1, '_id': 0})

        ip = ip.get('IP')

        return ip

    except(AttributeError):
        logger.error('Cannot find ip for {}'.format(club), exc_info=True)
        return None


def get_club(ip):
    ''' Get club name for ip address
    args: ip
    returns: club000'''

    myclient = pymongo.MongoClient("mongodb://localhost:27017/")

    # use database named "inventory"
    mydb = myclient['inventory']

    # use collection 'club_list'
    club_list = mydb['club_list']

    # query club
    club = club_list.find_one({'IP': ip}, {'Location': 1, '_id': 0})

    if club:
        club = club.get('Location')
        return club

    else:
        return None


def club_ips(club_list):
    ''' takes list of clubs to scan, and converts them to list of ips'''

    club_ip_list = []
    club_rgx = compile(cfg.club_rgx)
    ip_rgx = compile(cfg.ip_rgx)

    try:
        for item in club_list:
            club_ = club_rgx.search(item)
            ip_ = ip_rgx.search(item)

            if club_ is not None:
                club_ = str(club_.group(0))
                club_ip = get_club_ips(club_)
                if club_ip is not None:
                    club_ip_list.append(club_ip)
                else:
                    logger.debug('cannot find IP for {}'.format(club_))
                    not_connected.append(club_)
                    continue

            elif ip_ is not None:
                ip_ = str(ip_.group(0))
                club_ip_list.append(ip_)

            else:
                logger.warning('{} is not in the right format, try again.'.format(item))
                continue

        if len(club_ip_list):
            return club_ip_list
        else:
            return None

    except(OSError, AttributeError):
        if len(club_ip_list):
            logger.critical('There was a problem getting all IPs.', exc_info=True)
            return club_ip_list
        else:
            logger.critical('There was a problem getting IPs for clubs. Try again', exc_info=True)
            return None


def inv_args(ip_list):

    parser = ArgumentParser(description='Asset Inventory Script')
    parser.add_argument(
        '-club', '-c',
        nargs='*',
        help='Club Number in "club000" format or club IP')
    parser.add_argument(
        '-clubList', '-l',
        help='Club List in list of "club000" format or club IP')
    parser.add_argument(
        '-debug', '-d',
        action='store_true',
        help='-debug mode')
    inv_args = parser.parse_args()

    if inv_args.debug:
        logger.setLevel(DEBUG)
    else:
        # change to INFO after debugging
        logger.setLevel(DEBUG)

    if inv_args.club:
        arg_ips = club_ips(inv_args.club)
        if arg_ips:
            ips = arg_ips
            for ip in ips:
                scan_queue.append(ip)
        else:
            logger.error('Could not find club IP, exiting')
            exit()
    else:
        ips = ip_list
        for ip in ips:
            scan_queue.append(ip)

    return ips


def script_info():
    """ Information to display when script is done"""

    logger.info('The following {} clubs were scanned:'.format(len(clubs)))
    for item in clubs:
        logger.info(item)

    logger.info('The following {} hosts were not scanned:'
                .format(len(scan_queue)))
    for ip in scan_queue:
        club = get_club(ip)
        if club:
            logger.info(club)
        else:
            logger.info(ip)

    end = time()
    runtime = end - start
    runtime = str(timedelta(seconds=int(runtime)))
    logger.info('Script Runtime: {} '.format(runtime))
    for ip in scan_queue:
        club_number = get_club(ip)
        if club_number:
            club_queue.append(club_number)
        else:
            club_queue.append(ip)

    for ip in not_connected:
        club_number = get_club(ip)
        if club_number:
            not_scanned.append(club_number)
        else:
            not_scanned.append(ip)

    logger.info('The following {} hosts were not scanned because of a problem: '
                .format(len(not_scanned)))
    for item in not_scanned:
        logger.info(item)

    mail.send_mail(ctime(start),
                   runtime,
                   clubs,
                   club_queue,
                   scan_queue,
                   not_scanned,
                   api_status,
                   added,
                   restored,
                   updated,
                   deleted)


if __name__ == '__main__':
    main(inv_args(ips.get_ips()))
