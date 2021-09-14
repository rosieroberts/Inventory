#!/usr/bin/env python3

from os import path
from sys import exit
from json import decoder
from time import time
from re import compile
from copy import deepcopy
from datetime import timedelta
import requests
# import traceback
import urllib3

import lib.config as cfg
from lib import invbin


def main():
    """main function to run script, using get_ip_list from ips.py
    or using a specific list of ips

    Args:
        None

    Returns:
        None

    Raises:
        Does not raise an error.
    """

    start = time()
    all_diff = []
    all_api_payload = []
    add = []
    remove = []
    update = []
    connect_obj = None

    ips = invbin.RouterInfo().get_ips()

    header_added = False
    ip_regex = compile(r'(?:\d+\.){3}\d+')

    print(cfg.intro1)
    print(cfg.intro2)

    db_count = 0
    invbin.ApiConn().get_snipe()

    # truncating csv file if it was ran a prior time on same day to
    # avoid duplicate values
    full_csv = ('./scans/full_scans/full_scan{}.csv'
                .format(invbin.Assets.today.strftime('%m%d%Y')))
    if (path.exists(full_csv) and path.isfile(full_csv)):
        f = open(full_csv, "w+")
        f.close()

    for attempt in range(3):
        try:
            url_loc = cfg.api_url_get_locations
            response_loc = requests.request("GET",
                                            url=url_loc,
                                            headers=cfg.api_headers)
            loc_id_data = response_loc.json()
        except decoder.JSONDecodeError:
            loc_id_data = None
            print('Cannot get location information from API. Stopping Script')
            exit()

    for ip in ips:
        ip_address = ip_regex.search(ip)
        clb_runtime_str = time()
        print(ip)
        if ip_address:
            # connect to router and get connect object and device type
            # item returned [0]
            # device_type [1]
            router_connect = invbin.RouterInfo.connect(str(ip))

        try:
            if router_connect:
                connect_obj = router_connect[0]
                device_type = router_connect[1]
                if ip_address:
                    results = invbin.DeviceInfo.get_router_info(connect_obj, str(ip), device_type, loc_id_data)
                else:
                    results = None

                for item in results:
                    item['ID'] = invbin.ApiConn.get_id(item['Asset Tag'])

                results_copy = deepcopy(results)

                all_diff = invbin.Comparisons.diff(results_copy)

                if all_diff:
                    all_api_payload = invbin.ApiConn.api_payload(all_diff)

                    if all_api_payload:
                        add = all_api_payload[0]
                        remove = all_api_payload[1]
                        # update = all_api_payload[2]
                    invbin.ApiConn.api_call(results_copy[0]['Location'], add, remove)
                updated_results = invbin.SaveResults.save_results(results, str(ip))
                invbin.SaveResults.add_to_db(updated_results, db_count)
                db_count += 1
                invbin.SaveResults.csv(results, header_added)
                connect_obj.disconnect()

        except(urllib3.exceptions.ProtocolError):
            print('Remote end closed connection without response')
            print('Scanning next club....')
            continue

        clb_runtime_end = time()
        clb_runtime = clb_runtime_end - clb_runtime_str
        clb_runtime = str(timedelta(seconds=int(clb_runtime)))
        header_added = True

        if router_connect:
            if results:
                print('\n{} Scan Runtime: {} '
                      .format(results[0]['Location'], clb_runtime))
        else:
            print('\nClub Scan Runtime: {} '.format(clb_runtime))

    print('\nThe following {} hosts were not scanned:'
          .format(len(invbin.Assets.not_connected)))
    for item in invbin.Assets.not_connected:
        print(item)

    print('\nThe following {} clubs were scanned:'.format(len(invbin.Assets.clubs)))
    for item in invbin.Assets.clubs:
        print(item)

    end = time()
    runtime = end - start
    runtime = str(timedelta(seconds=int(runtime)))
    print('\nScript Runtime: {} '.format(runtime))

    return [add, remove, update]
