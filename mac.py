#!/usr/bin/env python3

import netmiko
from netmiko import ConnectHandler
from ipaddresses import get_final_ip_list
import ipaddress
import nmap
import config as cfg

not_connected = []

def connect(ip):
    '''' Connect to router using .1 address from each ip route from ip_list'''

    try:
        net_connect = ConnectHandler(device_type='cisco_ios',
                                     host=str(getSiteRouter(ip)),
                                     username=cfg.ssh['username'],
                                     password=cfg.ssh['password'])
        return net_connect

    except(netmiko.ssh_exception.NetMikoTimeoutException):
        print('Could not connect to ' + (host))
        not_connected.append(ip)


def getMacAddress(ip):
    ''' Returns Mac Addresses from each site ARP Table'''
    net_connect = connect(ip)
    # net connect will be none when connect() has an exception 
    # & cannot connect
    while net_connect is not None:

        # get list of subnets for each site
        siteSubnets = getSiteSubnets(ip)
#       siteSubnets = usableIP(ip)

#       get router for current route
#       siteRouter = getSiteRouter(ip)

        mac_list = []

#       send sh arp command for each subnet to get mac address and add to list
        for item in siteSubnets:
            mac = net_connect.send_command('sh arp ' + str(item))
            mac = mac.strip()[109:123]

            if len(mac) != 0:
                temp_list = []
                temp_list.append(item)
                temp_list.append(mac)
                mac_list.append(temp_list)

        print(len(mac_list))
        print(mac_list)
        return mac_list


# I still need to do this ...
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


# not used yet - none of the end users are showing up.
# use nmap to see whether or not a host is up and if it is add to list
# this list is a shorter list of subnets to getMacAddress() to use,
# reducing running time
def usableIP(ip):
    ''' Checks each site subnets for only hosts that are up & returns list'''
    host = str(ip)
    nmap_args = '-sn'
    scanner = nmap.PortScanner()
    scanner.scan(hosts=host, arguments=nmap_args)
    usable_host_list = []

    for ip in scanner.all_hosts():
        host = {'ip' : ip}

        if scanner[ip]['status']['state'] == 'up':
            print(scanner[ip]['status']['state'])
            usable_host_list.append(host['ip'])

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


main()
