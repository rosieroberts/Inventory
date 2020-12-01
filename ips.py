#!/usr/bin/env python3

from easysnmp import Session
from nmap import PortScanner
import re
from csv import reader
import config as cfg
from time import time
from datetime import timedelta

# Core router
session = Session(hostname=cfg.snmp['hostname'],
                  community=cfg.snmp['community'],
                  version=2)

# OIDs needed to get IP/mask information
oids = ['ip.21.1.1',
        'ip.21.1.11',
        'inetCidrRouteType',
        'inetCidrRouteProto',
        'inetCidrRouteStatus']


def get_ips():
    """ Get full list of IPs based on OID ip.21.1.11.
    Extract IP and subnet mask and add to ip_list. """
    split_list = []
    ip_list = []
    ip_list_f = []

    # for subnet mask to extract IPs and subnet masks and add to ful_ip_list
    subnet_masks = session.walk(oids[1])
    # regex to get ip address from oid value
    ip_regex = re.compile(r'(?:\d+\.){3}\d+$')
    # add values to list in format: ['ip/subnet mask']
    full_ip_list = []
    for item in subnet_masks:
        # easysnmp item.oid is OID from smpwalk
        ip = ip_regex.search(item.oid).group(0)
        # easysnmp uses item.value to get value for OID which is the mask
        full_ip_list.append('{}/{}'.format(ip, item.value))
    # split values in list to create a list of IPs w/ respective subnet masks
    # convert subnet masks to cidr notation
    # while it is being split and added to list
    # format: ['ip', 'subnet mask(/24)']

    for item in full_ip_list:
        # split item in two parts
        item = item.split('/')
        # subnet mask is split by '.' to get value of each octet
        # octet values are converted to bin and added up to get cidr notation
        # subnet mask is replaced with cidr notation mask and added to list
        item[1] = str(sum(bin(int(x)).count('1') for x in item[1].split('.')))
        split_list.append(item)

    # regex to search for IPs to include clubs and regional offices
    regex_include = re.compile(r'(^10\.([4-9]|[1-8][0-9]|9[0-6])\.)')
    regex_fort = re.compile(r'(^172\.([3][0-1])\.)')
    # search for included IPs in list
    for item in split_list:
        regex_value = regex_include.search(item[0])
        if regex_value:
            ip_list.append(item)
        regex_f_value = regex_fort.search(item[0])
        if regex_f_value:
            ip_list_f.append(item)
    # returns list - ip = item[0] and mask = item[1]

    for item in ip_list_f:
        print(item)

    return [ip_list, ip_list_f]


def fortigate_ips(ip_list_f):
    """ Get ips from fortigate"""
    start = time()
    ip_list = []
    hostname_list = []
    for list in ip_list_f:
        ip_list.append(list[0])

    for ip in ip_list:
        host = str(ip)
        nmap_args = '-sn'
        scanner = PortScanner()
        scanner.scan(hosts=host, arguments=nmap_args)
        hosts = {}
        for ip in scanner.all_hosts():
            fgt = []
            hosts['ip'] = ip
            hosts['hostnames'] = None

            if 'hostnames' in scanner[ip]:
                hosts['hostnames'] = scanner[ip].hostname()

            club_num_rgx = re.compile(r'(^[0-9]{3}(?=-fgt-))', re.IGNORECASE)
            club_search = club_num_rgx.search(hosts['hostnames'])
            if club_search:
                hostname_list.append(hosts['hostnames'])
                fgt.append(ip)
                fgt.append(str(club_search))
                fgt_item = ','.join(fgt)
                print(fgt_item, '**')

    fgt_list = fortigate_list()

    for item in fgt_list:
        print(item)
    elapsed_time = time() - start
    elapsed_time = str(timedelta(seconds=int(elapsed_time)))
    print('Duration getting fortigate hosts: ', elapsed_time)

    return hostname_list


def fortigate_list():
    # get list of current fortigate ips/clubs

    fgt_list = []
    with open('fortigate.csv', newline='') as csvfile:
        f_list = reader(csvfile, delimiter=' ', quotechar='|')
        for row in f_list:
            fgt_list.append(row)
            print(row)

    return(fgt_list)


def always_exclude(ip_list):
    """ Get IPs to exclude from warehouse and TSC """
    always_exclude_list = []
    # clubs with fortinet
    # ***always_exclude_list.extend(cfg.exclude_list_add)
    # Regex to exclude warehouse | TSC
    regex = re.compile(r'(^10\.11\.163\.)|(^10\.11\.20[0-7]\.)')
    # search for items to exclude
    for item in ip_list:
        regex_value = regex.search(item[0])
        if regex_value:
            always_exclude_list.append(item[0])
    return(always_exclude_list)


def oid_exclude(oid, oid_value):
    """ Returns list of excluded IPs from specific OID values from argument """
    oid_exclude_list = []
    regex = re.compile(r'(?<=^1\.4\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    routes = session.walk(oid)
    for item in routes:
        if item.value != (oid_value):
            ip_value = regex.search(item.oid_index)
            if ip_value:
                oid_exclude_list.append(ip_value.group(0))
    return(oid_exclude_list)


def get_ip_list():
    """ Get final IP list by removing exclude_list from ip_list """

    full_ip_list = get_ips()

    # find hosts that are always excluded
    exclude_list = always_exclude(full_ip_list[0])

    # -fortinet_list = fortinet_ips(full_ip_list[1])

    # find hosts that are not found via ospf and add them to exclude_list
    exclude_list.extend(list(oid_exclude(oids[3], '13')))
    # find hosts that are not remote and add them to exclude_list
    exclude_list.extend(list(oid_exclude(oids[2], '4')))
    # find hosts that are not up and add them to exclude_list
    exclude_list.extend(list(oid_exclude(oids[4], '1')))
    # compare IP list with excluded_list
    # and remove excluded items, add to final_list
    final_list = [item for item in full_ip_list[0] if item[0] not in exclude_list]
    # join ip_list and mask and return final list with usable ips/mask
    # format: ['ip/mask']

    for item in final_list:
        print(item[0])

    ips_with_mask = ['/'.join(x) for x in final_list]
    fortigate_list = fortigate_ips(full_ip_list[1])

    # -for item in fortinet_list:
    #   -ips_with_mask.append(item)

    # for item in ips_with_mask:
    #    print(item)

    return(ips_with_mask)

get_ip_list()
