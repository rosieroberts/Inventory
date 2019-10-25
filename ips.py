#!/usr/bin/env python3

from easysnmp import Session
import re
import config as cfg

exclude_list = []

# Core router
session = Session(hostname=cfg.snmp['hostname'],
                  community=cfg.snmp['community'],
                  version=2)

# OIDs
OIDs = ['ip.21.1.1',
        'ip.21.1.11',
        'inetCidrRouteType',
        'inetCidrRouteProto',
        'inetCidrRouteStatus']


def get_ips():
    ''' Get full list of IPs based on OID ip.21.1.11.
    Extract IP and subnet mask and add to ip_list.'''

    IPlist = []
    final = []

    # for subnet mask to extract IPs and subnet masks and add to ip_list
    subnet_masks = session.walk('ip.21.1.11')

    # regex to get ip address from oid value
    oid_regex = re.compile(r'(?:\d+\.){3}\d+$')

    # add values to list in format: ['ip/subnet mask']
    full_ip_list = list('{}/{}'.format(oid_regex.search(item.oid).group(0),
                        item.value) for item in subnet_masks)

    # split values in list to create a nested list with IPs and subnet masks
    # convert subnet masks to cidr notation
    # while it is being split and added to list
    # format: ['ip', 'subnet mask(/24)']
    for item in full_ip_list:
        item = item.split('/')
        item[1] = str(sum(bin(int(x)).count('1') for x in item[1].split('.')))
        IPlist.append(item)

    # regex to search for IPs to include. Club | POS
    regex_include = re.compile(r'(^10\.([4-9]|[1-8][0-9]|9[0-6])\.)')  # |'
    #                          r'(^172\.22\.(6[4-9]|[78][0-9]|9[0-5])\.)')

    for item in IPlist:
        regex_value = regex_include.search(item[0])

        if regex_value:
            final.append(item)

    return(final)


def always_exclude():
    ''' Get IPs to exclude from warehouse and TSC'''

    exclude_list.append('10.5.252.0')

    # Regex to exclude warehouse | TSC
    regex = re.compile(r'(^10\.11\.163\.)|(^10\.11\.20[0-7]\.)')

    ip_list = get_ips()

    for item in ip_list:
        regex_value = regex.search(item[0])

        if regex_value:
            exclude_list.append(item[0])
    print(exclude_list)
    return(exclude_list)


def exclude(OID, OID_value):
    ''' Returns list of excluded IPs from specific OID values from argument'''

    regex = re.compile(r'(?<=^1\.4\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    routes = session.walk(OID)
    for item in routes:
        if item.value != (OID_value):
            ip_value = regex.search(item.oid_index)
            if ip_value:
                exclude_list.append(ip_value.group(0))
    return(exclude_list)


def get_ip_list():
    ''' Get final IP list by removing exclude_list from ip_list'''

    #   get list of all ips from SNMPWalk
    ip_list = get_ips()

    #   get list of always excluded ips
    always_exclude()

    #   find hosts that are not found via ospf and add them to exclude_list
    exclude('inetCidrRouteProto', '13')

    #   find hosts that are not remote and add them to exclude_list
    exclude('inetCidrRouteType', '4')

    #   find hosts that are not up and add them to exclude_list
    exclude('inetCidrRouteStatus', '1')

    #   compare IP list with excluded_list
    #   and remove excluded items, add to final_list
    final_list = [item for item in ip_list if item[0] not in exclude_list]

    #   join ip_list and mask and return final list with usable ips/mask
    #   format: ['ip/mask']
    ips_with_mask = ['/'.join(x) for x in final_list]

    # for item in ips_with_mask:
    #    print(item)
    # for item in final_list:
    #    print(item[0])

    return(ips_with_mask)


get_ip_list()
