#!/usr/bin/env python3

from netmiko import ConnectHandler
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException)
from paramiko.ssh_exception import SSHException
from paramiko import channel
from ips import get_ip_list
from ipaddress import ip_network
from nmap import PortScanner
import config as cfg
from json import dumps
from time import time
from re import compile
import traceback
from netaddr import EUI, mac_unix_expanded
from netaddr.core import NotRegisteredError
from csv import DictWriter

start = time()
not_connected = []
clubs = []
mac_ouis = []


def connect(host):
    """ Connect to router using .1 address from each ip route from ip_list"""
    print(host)
    tries = 0
    for _ in range(1):
        for _ in range(2):
            tries += 1
            startconn = time()
            try:
                net_connect = ConnectHandler(device_type='cisco_ios',
                                             host=host,
                                             username=cfg.ssh['username'],
                                             password=cfg.ssh['password'],
                                             blocking_timeout=20)
                endconn = time()
                time_elapsed = endconn - startconn
                print(time_elapsed)
                return net_connect

            except(NetMikoTimeoutException,
                   NetMikoAuthenticationException,
                   SSHException,
                   OSError,
                   ValueError):

                print(tries)
                traceback.print_exc()
                # if connection fails and an Exception is raised,
                # scan host to see if port 22 is open,
                # if it is open try to connect again
                # if it is closed, return None and exit
                nmap_args = 'p22'
                scanner = PortScanner()
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
                if tries == 1:
                    print('Exception, trying to connect again ' + (host))

        # exhausted all tries to connect, return None and exit
        print('Connection to the following device is not possible: ' + (host))
        not_connected.append(host)
        return None


def routerConnection(host):
    router_connect = connect(host)
    return router_connect


def getRouterInfo(conn, host):
    """ Return ip, location, hostname, mac address and status for
    all devices in a site and append to a json file"""
    start2 = time()

    

    club_result = clubID(conn, host)

    results = []
    mac_regex = compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = compile(r'(?:\d+\.){3}\d+')
    not_added = []

    for attempt in range(1):

        for _ in range(1):

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
                            deviceType = getDeviceType(ip_result, club_result)
                            
                            octets = ip_result.split('.')
                            last_octet = int(octets[-1])
                            first_octet = int(octets[0])
                            
                            mac_result = macAddressFormat(mac_result)
                            vendor = getOuiVendor(mac_result)

                            hostname = getHostnames(ip_result)

                            if hostname is None:
                                continue

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

                            if (len(results)) == 0:
                                print(len(results))
                                if first_octet == 10 and last_octet == 1:
                                    print(first_octet, last_octet)
                                    results.append(subnet_mac)
                                else:
                                    not_added.append(subnet_mac)
                                    print(not_added)

                            if (len(results)) > 0 and subnet_mac['mac'] != results[0]['mac']):
                                print(len(results), subnet_mac, results[0]['mac'])
                                results.append(subnet_mac)

                    if not_added != 0:
                        for item in not_added:
                            if item['mac'] != results[0]['mac']):
                                print(item['mac'], results[0]['mac'], item)
                                results.append(item)

                    clubs.append(club_result)

                except(OSError):

                    if attempt == 0:
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

    end2 = time()
    runtime2 = end2 - start2
    print(runtime2)

    return results


def writeToFiles(results, header_added):
    """ function to print and add results to .json and .csv files"""
    if len(results) != 0:
        for item in results:
            print(item)
        output = open('inventory10-11.json', 'a+')
        output.write(dumps(results))
        output.close()

        keys = results[0].keys()
        with open('inventory10-11.csv', 'a') as csvfile:
            csvwriter = DictWriter(csvfile, keys)
            if header_added is False:
                csvwriter.writeheader()
            csvwriter.writerows(results)


def getDeviceType(host, club_result):
    """ Returns the device type based on ip address"""
    device_type = 'null'

    octets = host.split('.')
    last_octet = int(octets[-1])
    first_octet = int(octets[0])
    second_octet = int(octets[1])

    if club_result[:4].lower() == 'club':

        if first_octet == 10:
            device_type = cfg.clubDeviceType(last_octet)

        if first_octet == 172 and second_octet == 24:
            device_type = 'Phone'

        #  IP not within usual configuration
        if host == cfg.club910:
            device_type = cfg.clubDeviceType(last_octet)

        # ISP provider for club 963. Not usual instance
        if host == cfg.club963:
            device_type = 'Router (ISP Provider)'

    if club_result[:3].lower() == 'reg':

        if first_octet == 10:
            device_type = cfg.regionDeviceType(last_octet)

        if first_octet == 172 and second_octet == 23:
            device_type = 'Phone'

    return device_type


def getOuiVendor(mac):
    """ Returns vendor for each device based on mac address """
    oui = macOUI(mac)

    try:
        mac_oui = EUI(mac).oui
        vendor = mac_oui.registration().org
        return vendor

    # Some of the OUIs are not included in the IEEE.org txt used in netaddr.
    # the list of OUIs here is gatherered from Wireshark,
    # the lists above are hardcoded because the list is rather small
    except(NotRegisteredError):
        vendor = None

        if oui in cfg.cisco:
            vendor = 'Cisco Systems, Inc'
        if oui in cfg.dell:
            vendor = 'Dell Inc.'
        if oui in cfg.asustek:
            vendor = 'AsustekC ASUSTek COMPUTER INC.'
        if oui in cfg.HeFei:
            vendor = 'LcfcHefe LCFC(HeFei) Electronics Technology co., ltd'
        if oui in cfg.meraki:
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

    club_rgx = compile(r'(?i)(Club[\d]{3})')
    reg_rgx = compile(r'(REG-)(10)[1-4](-)(ADD|POR|IRV|ENG|HOU)')

    for attempt in range(1):

        for attempt2 in range(1):

            if conn is not None:

                try:
                    club_info = conn.send_command('sh cdp entry *')
                    club_result = club_rgx.search(club_info)

                    if club_result is None:
                        club_result = reg_rgx.search(club_info)

                    if club_result is not None:
                        club_result = club_result.group(0)

                    else:
                        hostname = getHostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club is not None:
                            club_result = hostname_club.group(0)

                        else:
                            club_result = 'null'

                    return club_result

                except(OSError):
                    if attempt == 0:
                        print('Could not send command, cdp. Trying again')
                        break

                    if attempt == 1 and attempt2 == 0:
                        print('getting clubID from nmap hostname')
                        hostname = getHostnames(host)
                        hostname_club = club_rgx.search(hostname['hostnames'])

                        if hostname_club is not None:
                            club_result = hostname_club.group(0)

                        else:
                            print('could not get hostname')
                            club_result = 'null'

                    else:
                        print('could not get clubID')
                        club_result = 'null'

                    print('returning "null"')

                    return club_result


def getDeviceMac(router_conn):
    """ return list of mac addresses from a
    router arp table for a given subnet """
    router_maclist = []

    mac_regex = compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')

    if router_conn is not None:

        mac_table = router_conn.send_command('sh arp')
        mac_table_list = mac_table.splitlines()

        for item in mac_table_list:
            mac_result = mac_regex.search(item)

            if mac_result is not None:
                continue

            mac_result = mac_result.group(0)

            router_maclist.append(mac_result)
        router_maclist = set(router_maclist)

        router_maclist = [macAddressFormat(item) for item in router_maclist]

        return router_maclist

    else:
        return None


def getHostnames(ip):
    """ Scan local network for all hosts"""
    hosts = str(ip)
    nmap_args = '-sn'
    scanner = PortScanner()
    scanner.scan(hosts=hosts, arguments=nmap_args)

    for ip in scanner.all_hosts():

        host = {'ip': ip}

        if 'hostnames' in scanner[ip]:
            host['hostnames'] = scanner[ip].hostname()

        if 'status' in scanner[ip]:
            host['status'] = scanner[ip]['status']['state']

        return host


#  Function to return only a site router IP which ends in '.1'.
def getSiteRouter(ip):
    """ Returns router IP when called"""
    siteHosts = ip_network(ip)
    firstHost = next(siteHosts.hosts())
    return(firstHost)


# return all usable subnets for a given IP
def getSiteSubnets(ip):
    """ Returns all subnets per site when called"""
    siteHosts = ip_network(ip)
    allHosts = list(siteHosts.hosts())
    return(allHosts)


def main():
    """ main function to run, use get_ip_list for all sites
    or use a specific list of ips"""
    #ip_list = ['10.32.28.0/24', '10.8.17.0/24', '10.11.139.0/24', '10.16.11.0/24', '10.32.31.0/24']
    header_added = False
    ip_list = get_ip_list()

    for ip in ip_list:
        router_connect = routerConnection(str(getSiteRouter(ip)))
        results = getRouterInfo(router_connect, str(getSiteRouter(ip)))
        writeToFiles(results, header_added)

        if router_connect is not None:
            router_connect.disconnect()
        header_added = True

    print('The following ', len(not_connected), ' hosts were not scanned')
    print(not_connected)

    print('The following ', len(clubs), ' clubs were scanned')
    print(clubs)


main()

end = time()
runtime = end - start
print(runtime)
