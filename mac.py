#!/usr/bin/env python3

import netmiko
from netmiko import ConnectHandler
from ipaddresses import get_final_ip_list
import ipaddress
import nmap
import config as cfg
import subprocess as sp
import json
import time
import re

start = time.time()
not_connected = []
macs_not_included = []

def connect(host):
    '''' Connect to router using .1 address from each ip route from ip_list'''
    print(host)
    tries = 0
    for i in range(2):
        for attempt in range(5):
            tries += 1
            print(tries)
            try:
                net_connect = ConnectHandler(device_type='cisco_ios',
                                             host=host,
                                             username=cfg.ssh['username'],
                                             password=cfg.ssh['password'])
                return net_connect

            except(netmiko.ssh_exception.NetMikoTimeoutException,
                   netmiko.ssh_exception.NetMikoAuthenticationException,
                   OSError):

                # if connection fails and an Exception is raised,
                # scan host to see if port 22 is open, if it is try to connect again
                # if it is closed, return None and exit
                nmap_args = 'p22'
                scanner = nmap.PortScanner()
                scanner.scan(hosts=host, arguments=nmap_args)

                for ip in scanner.all_hosts():
                    h = {'ip' : ip}

                    if scanner[ip].has_tcp(22):
                       # print(scanner[ip].tcp(22))
                        if scanner[ip]['tcp'][22]['state'] == 'closed':
                            print('port 22 is showing closed for ' + (host))
                            not_connected.append(host)
                            return None
                            break
                        else:
                            print('Port 22 is open ')
                            break
                    else:
                        print('port 22 is closed for ' + (host))
                        not_connected.append(host)
                        return None
                        break

                print('Exception raised, trying to connect again ' +(host))

            # if connection was not possible and the error was not caught...
            else:
                print('Could not connect to ' + (host))
                break

        # Inner loop tries to connect 5 times
        else:
            print('failed after 5 tries to connect to ' + (host))

    # exhausted all tries to connect, return None and exit
    else:
        print('Connection to the following device is not possible: ' + (host))
        not_connected.append(host)
        return None


def getRouterInfo(ip):
    ''' Return ip, location, hostname, mac address and status for
    all devices in a site and append to a json file'''
    start2 = time.time()
    host = str(getSiteRouter(ip))
    net_connect = connect(host)
    results = []

    club_regex = re.compile(r'(?i)(Club[\d]{3})')
    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = re.compile(r'(?:\d+\.){3}\d+')

    if net_connect is not None:

        club_info = net_connect.send_command('sh cdp entry *')
        club_result = club_regex.search(club_info)
        if club_result != None:
            club_result = club_result.group(0)
        else:
            ip = getSiteRouter(ip)
            hostname = getHostnames(ip)
            hostname_club = club_regex.search(hostname['hostnames'])
            if hostname_club != None:
                club_result = hostname_club.group(0)

            else:
                club_result = 'null'


        arp_table = net_connect.send_command('sh arp')
        arp_list = arp_table.splitlines()

        for item in arp_list:

            ip_result = ip_regex.search(item)
            mac_result = mac_regex.search(item)

            if ip_result is not None and mac_result is not None:

                ip_result = ip_result.group(0)
                mac_result = mac_result.group(0)

                hostname = getHostnames(ip_result)

                if hostname == None:
                    continue

                subnet_mac = {'ip': ip_result,
                              'club': club_result,
                              'hostname': hostname['hostnames'],
                              'mac': mac_result,
                              'status': hostname['status']}
            else:
                continue

            results.append(subnet_mac)

        print(results)

    output = open('inventory9-6-2.json', 'a+')
    output.write(json.dumps(results))
    output.close()

    end2 = time.time()
    runtime2 = end2 - start2
    print(runtime2)

    net_connect.disconnect()
    return results


def validateMacs(ip):
    ''' mac addresses in Switch not found in Router '''
    # Need to figure out how to handle this'''

    switch_maclist = getSwitchMac(ip)
    router_maclist = getRouterMac(ip)

    if switch_maclist and router_maclist is not None:
        difference =[item for item in switch_maclist if item not in router_maclist]
        all_diff = []
        for item in difference:
            diff = []
            diff.append(ip)
            diff.append(item)
            all_diff.append(diff)

        print(all_diff)
        macs_not_included.append(all_diff)
        return all_diff
    else:
        print('Could not perform comparison ' + ip)
        return None

def getRouterMac(ip):
    ''' return list of mac addresses from a router arp table for a given subnet '''
    host = str(getSiteRouter(ip))
    net_connect = connect(host)
    rt_mac_list = []
    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')

    if net_connect is not None:

        mac_table = net_connect.send_command('sh arp')
        mac_table_list = mac_table.splitlines()
        for item in mac_table_list:
            mac_result = mac_regex.search(item)

            if mac_result == None:
                continue

            mac_result = mac_result.group(0)

            rt_mac_list.append(mac_result)
        mac_list = set(rt_mac_list)

        print('*************ROUTER**********')
        print(mac_list)
        print(len(mac_list))

        net_connect.disconnect()
        return mac_list

    else:
        return None


def getSwitchMac(ip):
    ''' return list of mac addressess from switch mac-tables for a given subnet'''
    host = str(getSiteSwitch(ip))
    net_connect = connect(host)
    sw_mac_list = []
    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')

    if net_connect is not None:

        mac_table = net_connect.send_command('show mac address-table')
        mac_table_list = mac_table.splitlines()

        for item in mac_table_list:
            string = item[2:4]
            if string.isdigit():
                mac_result = mac_regex.search(item)

                if mac_result == None:
                    continue

                mac_result = mac_result.group(0)

                sw_mac_list.append(mac_result)
        mac_list = set(sw_mac_list)

        print('*************SWITCH**********')
        print(mac_list)
        print(len(mac_list))

        net_connect.disconnect()
        return mac_list

    else:
        return None

def getHostnames(ip):

    # Scan local network for all hosts
    hosts = str(ip)
    nmap_args = '-sn'
    scanner = nmap.PortScanner()
    scanner.scan(hosts=hosts, arguments=nmap_args)

    host_list = []

    for ip in scanner.all_hosts():

        host = {'ip' : ip}

        if 'hostnames' in scanner[ip]:
            host['hostnames'] = scanner[ip].hostname()

            # Take out the .24hourfit.com string from hostname
            host['hostnames'] = host['hostnames'].replace('.24hourfit.com', '')

        if 'status' in scanner[ip]:
            host['status'] = scanner[ip]['status']['state']

        return host


#  Function to return only a site router IP which ends in '.1'.
def getSiteRouter(ip):
    ''' Returns router IP when called'''
    siteHosts = ipaddress.ip_network(ip)
    firstHost = next(siteHosts.hosts())
    return(firstHost)


# function to return only a site switch IP which ends in '.10'.
def getSiteSwitch(ip):
    ''' Returns switch IP when called'''
    siteHosts = ipaddress.ip_network(ip)
    allHosts = list(siteHosts.hosts())
    return(allHosts[9])


# return all usable subnets for a given IP
def getSiteSubnets(ip):
    ''' Returns all subnets per site when called'''
    siteHosts = ipaddress.ip_network(ip)
    allHosts = list(siteHosts.hosts())
    return(allHosts)


def main():
    #ip_list = ['10.8.1.0/24', '10.10.10.0/24']
    ip_list = get_final_ip_list()
    for ip in ip_list:
        getRouterInfo(ip)
        validateMacs(ip)
    print(not_connected)
    print(macs_not_included)

main()
end = time.time()
runtime = end - start
print(runtime)

