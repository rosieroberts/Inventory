#!/usr/bin/env python3

import netmiko
from netmiko import ConnectHandler
import paramiko
from ips import get_ip_list
import ipaddress
import nmap
import config as cfg
import json
import time
import re
import traceback
from netaddr import *

start = time.time()
not_connected = []
macs_not_included = []


def connect(host):
    """ Connect to router using .1 address from each ip route from ip_list"""
    print(host)
    tries = 0
    for i in range(1):
        for attempt in range(5):
            tries += 1

            try:
                net_connect = ConnectHandler(device_type='cisco_ios',
                                             host=host,
                                             username=cfg.ssh['username'],
                                             password=cfg.ssh['password'])
                return net_connect

            except(netmiko.ssh_exception.NetMikoTimeoutException,
                   netmiko.ssh_exception.NetMikoAuthenticationException,
                   paramiko.ssh_exception.SSHException,
                   OSError):

                print(tries)
                traceback.print_exc()
                # if connection fails and an Exception is raised,
                # scan host to see if port 22 is open,
                # if it is open try to connect again
                # if it is closed, return None and exit
                nmap_args = 'p22'
                scanner = nmap.PortScanner()
                scanner.scan(hosts=host, arguments=nmap_args)

                for ip in scanner.all_hosts():

                    if scanner[ip].has_tcp(22):

                        if scanner[ip]['tcp'][22]['state'] == 'closed':
                            print('port 22 is showing closed for ' + (host))
                            not_connected.append(host)
                            return None
                        else:
                            print('Port 22 is open ')
                            break
                    else:
                        print('port 22 is closed for ' + (host))
                        not_connected.append(host)
                        return None

                print('Exception raised, trying to connect again ' + (host))

    # exhausted all tries to connect, return None and exit
    print('Connection to the following device is not possible: ' + (host))
    not_connected.append(host)
    return None


def routerConnection(host):
    router_connect = connect(host)
    return router_connect


def switchConnection(host):
    switch_connect = connect(host)
    return switch_connect


def getRouterInfo(conn, host):
    """ Return ip, location, hostname, mac address and status for
    all devices in a site and append to a json file"""
    start2 = time.time()

    club_result = clubID(conn, host)

    results = []
    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = re.compile(r'(?:\d+\.){3}\d+')

    if conn is not None:

        arp_table = conn.send_command('sh arp')
        arp_list = arp_table.splitlines()

        for item in arp_list:

            ip_result = ip_regex.search(item)
            mac_result = mac_regex.search(item)

            if ip_result is not None and mac_result is not None:

                ip_result = ip_result.group(0)
                mac_result = mac_result.group(0)

                mac_result = macAddressFormat(mac_result)

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

    return results


def macOUI(mac):
    """ Return OUI from mac address passed in argument"""
    # get first three octets for oui
    oui = mac[:8]

    return oui


def macAddressFormat(mac):
    """ Return formatted version of mac address
    to identify device to format: XX:XX:XX:XX:XX:XX """

    formatted_mac = EUI(str(mac))
    formatted_mac.dialect = mac_unix_expanded
    formatted_mac = (str(formatted_mac).upper())

    return formatted_mac


def clubID(conn, host):
    """ Return clubID for router in argument"""

    club_rgx = re.compile(r'(?i)(Club[\d]{3})')

    for i in range(1):
        for j in range(1):
            if conn is not None:

                try:
                    club_info = conn.send_command('sh cdp entry *')
                    club_result = club_rgx.search(club_info)

                    if club_result != None:
                        club_result = club_result.group(0)

                    else:
                        hostname = getHostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club != None:
                            club_result = hostname_club.group(0)

                        else:
                            club_result = 'null'

                    return club_result

                except(OSError):
                    if i == 0:
                        print('Could not send command, trying again')
                        break

                    if i == 1 and j == 0:
                        print('getting clubID from nmap hostname')

                        hostname = getHostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club != None:
                            club_result = hostname_club.group(0)

                        else:
                            club_result = 'null'

                    else:
                        print('could not get clubID')
                        club_result = 'null'

                    return club_result


def validateMacs(router_maclist, switch_maclist, ip):
    """ mac addresses in Switch not found in Router """
    # Need to figure out how to handle this

    router_maclist, switch_maclist = getDeviceMac(router_maclist,
                                                  switch_maclist)

    if switch_maclist and router_maclist is not None:
        difference = [item for item in switch_maclist
                      if item not in router_maclist]

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


def getDeviceMac(router_conn, switch_conn):
    """ return list of mac addresses from a
    router arp table for a given subnet """
    router_maclist = []

    switch_maclist = []

    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')

    if router_conn and switch_conn is not None:

        mac_table = router_conn.send_command('sh arp')
        mac_table_list = mac_table.splitlines()

        for item in mac_table_list:
            mac_result = mac_regex.search(item)

            if mac_result == None:
                continue

            mac_result = mac_result.group(0)

            router_maclist.append(mac_result)
        router_maclist = set(router_maclist)

        mac_table = switch_conn.send_command('show mac address-table')
        mac_table_list = mac_table.splitlines()

        for item in mac_table_list:
            string = item[2:4]
            if string.isdigit():
                mac_result = mac_regex.search(item)

                if mac_result == None:
                    continue

                mac_result = mac_result.group(0)

                switch_maclist.append(mac_result)
        switch_maclist = set(switch_maclist)

        router_maclist = [macAddressFormat(item) for item in router_maclist]
        switch_maclist = [macAddressFormat(item) for item in switch_maclist]

        print('*************ROUTER**********')
        print(router_maclist)
        print(len(router_maclist))

        print('*************SWITCH**********')
        print(switch_maclist)
        print(len(switch_maclist))

        return router_maclist, switch_maclist

    else:
        return None


def getHostnames(ip):
    """ Scan local network for all hosts"""
    hosts = str(ip)
    nmap_args = '-sn'
    scanner = nmap.PortScanner()
    scanner.scan(hosts=hosts, arguments=nmap_args)

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
    """ Returns router IP when called"""
    siteHosts = ipaddress.ip_network(ip)
    firstHost = next(siteHosts.hosts())
    return(firstHost)


# function to return only a site switch IP which ends in '.10'.
def getSiteSwitch(ip):
    """ Returns switch IP when called"""
    siteHosts = ipaddress.ip_network(ip)
    allHosts = list(siteHosts.hosts())
    return(allHosts[9])


# return all usable subnets for a given IP
def getSiteSubnets(ip):
    """ Returns all subnets per site when called"""
    siteHosts = ipaddress.ip_network(ip)
    allHosts = list(siteHosts.hosts())
    return(allHosts)


def main():
    """ main function to run, use get_ip_list for all sites
    or use a specific list of ips"""
    # ip_list = ['10.10.46.0/24', '10.10.250.0/24']
    ip_list = get_ip_list()
    for ip in ip_list:
        router_connect = routerConnection(str(getSiteRouter(ip)))
        switch_connect = switchConnection(str(getSiteSwitch(ip)))
        getRouterInfo(router_connect, str(getSiteRouter(ip)))
        validateMacs(router_connect, switch_connect, ip)
        router_connect.disconnect()
        switch_connect.disconnect()

    print(not_connected)
    print(macs_not_included)


main()
end = time.time()
runtime = end - start
print(runtime)
