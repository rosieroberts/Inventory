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

def connect(ip):
    '''' Connect to router using .1 address from each ip route from ip_list'''
    print(ip)
    openSSHRoutes = SSHRoutes()
    
    host = str(getSiteRouter(ip))
    
    if host in openSSHRoutes: 

        try:
            net_connect = ConnectHandler(device_type='cisco_ios',
                                         host=host,
                                         username=cfg.ssh['username'],
                                         password=cfg.ssh['password'])
            return net_connect

        except(netmiko.ssh_exception.NetMikoTimeoutException,
               netmiko.ssh_exception.NetMikoAuthenticationException):

            print('Could not connect to ' + (host))
            not_connected.append(ip)

    else:
        print('Port 22 is not open for ' + (host))
        not_connected.append(ip)      


def getMacAddress(ip):
    start2 = time.time()
    net_connect = connect(ip)
    mac_list = []

    club_regex = re.compile(r'(Club[\d]{3})')
    mac_regex = re.compile(r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})')
    ip_regex = re.compile(r'(?:\d+\.){3}\d+')

    if net_connect is not None:

        club_info = net_connect.send_command('sh cdp entry *')
        club_result = club_regex.search(club_info)
        if club_result != None:
            club_result = club_result.group(0)
        else:
            club_result = ''

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

            mac_list.append(subnet_mac)

        print(mac_list)

    output = open('inventory2.json', 'a+')
    output.write(json.dumps(mac_list))
    output.close()

    end2 = time.time()
    runtime2 = end2 - start2
    print(runtime2)

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

        if 'status' in scanner[ip]:
            host['status'] = scanner[ip]['status']['state']

            return host


# find only the routes to connect() that have 22 open
def SSHRoutes():
    ''' Checks if route has port 22 open and returns only those routers that do'''

    ip_list = get_final_ip_list()
    noSSHroutes = []
    sshRoutes = []
    for ip in ip_list:
        host = str(getSiteRouter(ip))
        sshRoutes.append(host)

        nmap_args = '-p22'
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, arguments=nmap_args)


        for ip in scanner.all_hosts():
            host = {'ip' : ip}

            if scanner[ip]['tcp'][22]['state'] == 'closed':
                noSSHroutes.append(ip)

    sshRoutes = [item for item in sshRoutes if item not in noSSHroutes]

    return sshRoutes


# not used yet - 
# use 'ping' to see whether or not a host is up and if it is add to list
def usableIP(ip):
    ''' Checks each site subnets for only hosts that are up & returns list'''
    usable_host_list = []

    status,result = sp.getstatusoutput('ping -c1 -w2 ' + ip)

    if status == 0:
        usable_host_list.append(ip)
        print('System ' + ip + ' is UP!!!')
    else:
        print('System ' + ip + ' is DOWN!!!')


    print(usable_host_list)
    return usable_host_list


# function to return only a site router IP which ends in '.1'
#  This address will be used for getting router ARP
def getSiteRouter(ip):
    ''' Returns router IP when called'''
    siteHosts = ipaddress.ip_network(ip)
    firstHost = next(siteHosts.hosts())
    return(firstHost)


# function to return only a site switch IP which ends in '.10'.
# This address will be used for getting switch mac tables
def getSiteSwitch(ip):
    ''' Returns switch IP when called'''
    siteHosts = ipaddress.ip_network(ip)
    allHosts = list(siteHosts.hosts())
    print(allHosts[9])
    return(allHosts[9])


# return all usable subnets for a given IP
def getSiteSubnets(ip):
    ''' Returns all subnets per site when called'''
    siteHosts = ipaddress.ip_network(ip)
    allHosts = list(siteHosts.hosts())
    return(allHosts)


def main():
    
    ip_list = get_final_ip_list()
    for ip in ip_list:
        getMacAddress(ip)
    print(not_connected)


main()
#getMacAddress('')
end = time.time()
runtime = end - start
print(runtime)

