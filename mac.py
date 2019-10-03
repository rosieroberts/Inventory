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
import urllib
import csv

start = time.time()
not_connected = []
macs_not_included = []
clubs = []
mac_ouis = []
mac_ouis2 = []

def connect(host):
    """ Connect to router using .1 address from each ip route from ip_list"""
    print(host)
    tries = 0
    for i in range(1):
        for attempt in range(1):
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
                   OSError,
                   ValueError):

                print(tries)
                # traceback.print_exc()
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
    # ips that do not have a switch, therefore there is no way to
    # do a comparison, skip
    excluded_ips = ['10.11.166.10', '10.11.189.10']

    if host not in excluded_ips:
        switch_connect = connect(host)

    else:
        switch_connect = None
        print('There is no switch for ' + host)

    return switch_connect


def getRouterInfo(conn, host):
    """ Return ip, location, hostname, mac address and status for
    all devices in a site and append to a json file"""
    start2 = time.time()

    club_result = clubID(conn, host)

    results = []
    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = re.compile(r'(?:\d+\.){3}\d+')

    for i in range(1):

        for j in range(1):

            if conn is not None:

                try:

                    arp_table = conn.send_command('sh arp')
                    arp_list = arp_table.splitlines()
 
                    for item in arp_list:
                        
                        ip_result = ip_regex.search(item)
                        mac_result = mac_regex.search(item)

                        if ip_result is not None and mac_result is not None:

                            ip_result = ip_result.group(0)
                            mac_result = mac_result.group(0)
                            deviceType = getDeviceType(ip_result)
 
                            mac_result = macAddressFormat(mac_result)
                            vendor = getOuiVendor(mac_result)

                            hostname = getHostnames(ip_result)

                            if hostname == None:
                                continue

                            print(ip_result, mac_result, vendor)
                            subnet_mac = {'ip': ip_result,
                                          'club': club_result,
                                          'device': deviceType,
                                          'vendor': vendor, 
                                          'hostname': hostname['hostnames'],
                                          'mac': mac_result,
                                          'status': hostname['status']}

                            # The first value added to 'results'
                            # is the router value. Subsequently, the rest
                            # of the mac values are compared to the first
                            # value. If the mac address is the same,
                            # values are not written to 'results' to avoid
                            # duplicate values from final list.

                            if len(results) == 0 or subnet_mac['mac'] != results[0]['mac']:
                                results.append(subnet_mac)

                    clubs.append(club_result)

                except(OSError):

                    if i == 0:
                        print('Could not send cmd "sh arp", trying again')
                        break

                    else:
                        print('Could not get arp table ' + (host))
                        not_connected.append(host)
                        failed_results = {'host': host,
                                          'club': club_result,
                                          'status': 'could not get arp table'}
                        results.append(failed_results)
                        continue
    for item in results:
        print(item)

    output = open('inventory9-30.json', 'a+')
    output.write(json.dumps(results))
    output.close()
    
    keys = results[0].keys()
    with open('inventory.csv','a') as csvfile:
        csvwriter = csv.DictWriter(csvfile, keys)
        csvwriter.writeheader()
        csvwriter.writerows(results)
      

    end2 = time.time()
    runtime2 = end2 - start2
    print(runtime2)

    return results


def getDeviceType(host):
    """ Returns the device type based on ip address"""
    device_type = 'null'

    octets = host.split('.')
    last_octet = int(octets[-1])
    first_octet = int(octets[0])
    second_octet = int(octets[1])
 
    if first_octet == 10:
        device_type = cfg.deviceType(last_octet)

    if first_octet == 172 and second_octet == 24:
        device_type = cfg.phoneDevice(first_octet, second_octet)

    return device_type


def getOuiVendor(mac):
    """ Returns vendor for each device based on mac address """
    oui = macOUI(mac)
    print(oui)
    cisco = ['54:BF:64', # not working?
             '00:7E:95',
             '50:F7:22',
             '00:72:78',
             '68:2C:7B',
             '00:AA:6E', # not working?
             '00:D6:FE', # not working?
             '00:3C:10',
             '0C:D0:F8',
             '50:F7:22',
             '70:0B:4F',
             '70:1F:53',
             'B0:90:7E',
             '00:45:1D'] # not working?

    meraki = ['E0:CB:BC']

    asustek = ['2C:FD:A1',
               '0C:9D:92',
               '18:31:BF',
               '4C:ED:FB',
               'B0:6E:BF']

    HeFei = ['8C:16:45']

    dell = ['6C:2B:59',
            'B8:85:84',
            '54:BF:64',
            '50:9A:4C',
            'E4:B9:7A',
            '8C:EC:4B',
            'D8:9E:F3']

    try:
        mac_oui = EUI(mac).oui
        vendor = mac_oui.registration().org
        return vendor

    # Some of the OUIs are not included in the IEEE.org txt used in netaddr.
    # the list of OUIs here is gatherered from Wireshark,
    # the lists above are hardcoded because the list is rather small
    except(NotRegisteredError):
        vendor = None

        if oui in cisco:
            vendor = 'Cisco Systems, Inc'
        if oui in dell:
            vendor = 'Dell Inc.'
        if oui in asustek:
            vendor = 'AsustekC ASUSTek COMPUTER INC.'
        if oui in HeFei:
            vendor = 'LcfcHefe LCFC(HeFei) Electronics Technology co., ltd'
        if oui in meraki:
            vendor = 'CiscoMer Cisco Meraki'

        mac_ouis.append(oui)

        return vendor


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
                        print('Could not send command, cdp. Trying again')
                        break

                    if i == 1 and j == 0:
                        print('getting clubID from nmap hostname')
                        hostname = getHostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club != None:
                            club_result = hostname_club.group(0)

                        else:
                            print('could not get hostname')
                            club_result = 'null'

                    else:
                        print('could not get clubID')
                        club_result = 'null'

                    print('returning "null"')

                    return club_result


def validateMacs(router_conn, switch_conn, ip):
    """ mac addresses in Switch not found in Router """
    # Need to figure out how to handle this

    if router_conn and switch_conn is not None:

        router_maclist, switch_maclist = getDeviceMac(router_conn,
                                                      switch_conn)

        difference = [item for item in switch_maclist
                      if item not in router_maclist]

        for item in difference:

            diff = {'ip': ip,
                    'club': clubs[-1],
                    'mac': item}
                
            macs_not_included.append(diff)

            print(diff)

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
    ip_list = ['10.10.54.0/24', '10.6.16.0/24', '10.96.9.0/24', '10.11.166.0/24']
    # ip_list = get_ip_list()
    for ip in ip_list:
        router_connect = routerConnection(str(getSiteRouter(ip)))
        switch_connect = switchConnection(str(getSiteSwitch(ip)))
        getRouterInfo(router_connect, str(getSiteRouter(ip)))
        validateMacs(router_connect, switch_connect, ip)
        if router_connect is not None:
            router_connect.disconnect()
        if switch_connect is not None:
            switch_connect.disconnect()

    ouis = set(mac_ouis)
    
    print('The following OUI vendors were not found ')
    for item in ouis:
        print(item)

    print('The following ', len(not_connected), ' hosts were not scanned')
    print(not_connected)

    print('The following ', len(clubs), ' clubs were scanned')
    print(clubs)

    print('The following ', len(macs_not_included), ' devices were not included in the report')
    print(macs_not_included)

main()

end = time.time()
runtime = end - start
print(runtime)
