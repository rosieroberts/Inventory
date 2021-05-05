#!/usr/bin/env python3

from easysnmp import Session
import re
import config as cfg

# Core router
session = Session(hostname=cfg.snmp['hostname'],
                  community=cfg.snmp['community'],
                  version=2)

# OIDs needed to get IP/mask information
oid = 'ip.21.1.11'


def get_ips():
    """ Get full list of IPs based on OID ip.21.1.11.
    Extract IP and subnet mask and add to ip_list. """
    split_list = []
    ip_list = []

    # for subnet mask to extract IPs and subnet masks and add to ful_ip_list
    subnet_masks = session.walk(oid)
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
    regex_ip = re.compile(r'(^172\.([3][0-1])\.)')
    # search for included IPs in list
    for item in split_list:
        regex_value = regex_ip.search(item[0])
        if regex_value:
            ip_list.append(item)

    f_list = []
    for item in ip_list:
        f_list.append(item[0])

    final_list = [item for item in f_list if item not in cfg.exclude_ips]

    return final_list

