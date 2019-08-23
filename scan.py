#! /usr/bin/env python3

from nmap import PortScanner
import csv
from getmac import get_mac_address


# Scan local network for all hosts

def scan(ip):
    hosts = str(ip)
    nmap_args = '-sn'
    scanner = PortScanner()
    scanner.scan(hosts=hosts, arguments=nmap_args)

    host_list = []

    for ip in scanner.all_hosts():

        host = {'ip' : ip}

        if 'hostnames' in scanner[ip]:
            host['hostnames'] = scanner[ip].hostname()

        if 'status' in scanner[ip]:
            host['status'] = scanner[ip]['status']['state']

        host['mac'] = get_mac_address(ip=ip, network_request=True)

        host_list.append(host)

    with open('scan_output.csv', 'w') as csvfile:
        fieldnames = ['ip', 'mac', 'status', 'hostnames']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(host_list)

    return host_list

