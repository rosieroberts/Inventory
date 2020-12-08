#!/usr/bin/env python3

from easysnmp import Session
from nmap import PortScanner
from ipaddress import ip_network
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

    #    for item in ip_list_f:
    #        print(item)

    return [ip_list, ip_list_f]


def get_fortigate_ips(ip_list_f):
    # Get ips from fortigate using nmap, looking for -fgt flag in hostname
    start = time()
    print('get_fortigate_ips', start)
    ip_list = []
    hostname_list = []
    gen_fgt_list = []
    gen_ip_list = []

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
                club_search = club_search.group(0)
                hostname_list.append(hosts['hostnames'])
                fgt.append(str(club_search))
                fgt.append(ip)
                gen_ip_list.append(ip)
                fgt_item = ','.join(fgt)
                gen_fgt_list.append(fgt_item)

    
    elapsed_time = time() - start
    elapsed_time = str(timedelta(seconds=int(elapsed_time)))
    print('Duration getting fortigate hosts: ', elapsed_time)

    return gen_fgt_list


def final_fgt(gen_fgt_list, fgt_list):
    # compare generated list with main list of fortigate clubs to make sure
    # all clubs are included

    print('final_fgt')
    list_set = set(fgt_list)
    gen_list_set = set(gen_fgt_list)

    not_in_fgt_list = [item for item in gen_fgt_list if item not in list_set]

    not_in_gen_fgt_list = [item for item in fgt_list if item not in gen_list_set]

    fgt_list = gen_fgt_list + not_in_gen_fgt_list

    final_fgt_list = [item[4:] for item in fgt_list]

    return final_fgt_list



def csv_fortigate_list():
    # get list of current fortigate ips/clubs
    print('csv_fortigate_list')
    fgt_list = []
    with open('fortigate.csv', newline='') as csvfile:
        f_list = reader(csvfile, delimiter=' ', quotechar='|')
        for row in f_list:
            fgt_list.append(row)

    fgt_list_flat = [item for sublist in fgt_list for item in sublist]

    return(fgt_list_flat)


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



def get_ip_list():
    #Get final IP list by removing exclude_list from ip_list

    full_ip_list = get_ips()

    # find hosts that are always excluded
    exclude_list = always_exclude(full_ip_list[0])

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

    #for item in final_list:
     #   print(item[0])

    ips_with_mask = ['/'.join(x) for x in final_list]

    fgt_ips = final_fgt(get_fortigate_ips(full_ip_list[1]), csv_fortigate_list()) 


    for item in ips_with_mask:
        print(item)
    for item in fgt_ips:
        print(item)

    cisco_ips = []
    for ip in ips_with_mask:
        cisco_router_ip = get_site_router(ip)
        cisco_router_ip = str(cisco_router_ip)
        cisco_ips.append(cisco_router_ip)


    final_ip_list = cisco_ips + fgt_ips

    return final_ip_list


get_ip_list()

