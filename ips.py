#!/usr/bin/env python3

from easysnmp import Session
import re
import config as cfg

exclude_list = []

# Core router
session = Session(hostname=cfg.snmp2['hostname'],
                  community=cfg.snmp['community'],
                  version=2)

# OIDs needed to get IP/mask information
OIDs = ['ip.21.1.1',
        'ip.21.1.11',
        'inetCidrRouteType',
        'inetCidrRouteProto',
        'inetCidrRouteStatus']


def get_ips():
    """ Get full list of IPs based on OID ip.21.1.11.
    Extract IP and subnet mask and add to ip_list. """

    split_list = []
    ip_list = []

    # for subnet mask to extract IPs and subnet masks and add to ful_ip_list
    subnet_masks = session.walk('ip.21.1.11')
    # regex to get ip address from oid value
    oid_regex = re.compile(r'(?:\d+\.){3}\d+$')
    # add values to list in format: ['ip/subnet mask']
    full_ip_list = []
    for item in subnet_masks:
        ip = oid_regex.search(item.oid).group(0)
        full_ip_list.append('{}/{}'.format(ip, item.value))

    # split values in list to create a list of IPs w/ respective subnet masks
    # convert subnet masks to cidr notation
    # while it is being split and added to list
    # format: ['ip', 'subnet mask(/24)']
    for item in full_ip_list:
        # split item in two parts
        item = item.split('/')
        # subnet mask is split by '.' to get value of each octet
        # values of octets are converted to binary then added to get cidr not
        # subnet mask is replaced with cidr notation mask and added to list
        item[1] = str(sum(bin(int(x)).count('1') for x in item[1].split('.')))
        split_list.append(item)

    # regex to search for IPs to include clubs and regional offices
    regex_include = re.compile(r'(^10\.([4-9]|[1-8][0-9]|9[0-6])\.)')

    for item in split_list:
        regex_value = regex_include.search(item[0])
        if regex_value:
            ip_list.append(item)

    return(ip_list)


def always_exclude():
    """ Get IPs to exclude from warehouse and TSC """

    # clubs with fortinet
    exclude_list.extend(cfg.exclude_list_add)
    # Regex to exclude warehouse | TSC
    regex = re.compile(r'(^10\.11\.163\.)|(^10\.11\.20[0-7]\.)')
    ip_list = get_ips()

    for item in ip_list:
        regex_value = regex.search(item[0])
        if regex_value:
            exclude_list.append(item[0])
    return(exclude_list)


def exclude(oid, oid_value):
    """ Returns list of excluded IPs from specific OID values from argument """

    regex = re.compile(r'(?<=^1\.4\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    routes = session.walk(oid)
    for item in routes:
        if item.value != (oid_value):
            ip_value = regex.search(item.oid_index)
            if ip_value:
                exclude_list.append(ip_value.group(0))
    return(exclude_list)


def get_ip_list():
    """ Get final IP list by removing exclude_list from ip_list """

    # get list of all ips from SNMPWalk
    ip_list = get_ips()
    # get list of always excluded ips
    always_exclude()
    # find hosts that are not found via ospf and add them to exclude_list
    exclude('inetCidrRouteProto', '13')
    # find hosts that are not remote and add them to exclude_list
    exclude('inetCidrRouteType', '4')
    # find hosts that are not up and add them to exclude_list
    exclude('inetCidrRouteStatus', '1')
    # compare IP list with excluded_list
    # and remove excluded items, add to final_list
    final_list = [item for item in ip_list if item[0] not in exclude_list]
    # join ip_list and mask and return final list with usable ips/mask
    # format: ['ip/mask']
    ips_with_mask = ['/'.join(x) for x in final_list]
    # for item in ips_with_mask:
    #    print(item)
    # for item in final_list:
    #    print(item[0])

    return(ips_with_mask)


get_ip_list()
