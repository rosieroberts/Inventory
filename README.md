**Inventory**
is a tool used to get information from all devices connected to each location in the company.

*-IP Address*
*-Location*
*-Asset Tag*
*-Device Type*
*-Vendor*
*-Hostname*
*-Mac Address*
*-Status*


How it works:

_**ips.py:**_

`get_ips():`
Uses [Session](https://github.com/kamakazikamikaze/easysnmp/blob/master/easysnmp/session.py) from [easysnmp](https://github.com/kamakazikamikaze/easysnmp) to connect to the main router and perform an SNMPWalk. Using specific OIDs, IP and mask information is extracted using regex and addded to a list with values combined in ip/subnet_mask format (CIDR notation).

`always_exclude():`
Creates list of excluded IPs that do not need to be included in final IP list in X.X.X.0 format

`exclude():`
Returns list of excluded IPs from specific OID values

`get_ip_list():`
Returns final IP list by removing exclude_list from ip_list in X.X.X.0/mask format


_**inventory.py**_

`connect()` Uses ConnectHandler from [netmiko](https://github.com/ktbyers/netmiko) to connect to each location's router via SSH. It attempts to connect twice before it quits and moves on to the next location. Returns a connection object used in other functions.

`getRouterInfo` Uses connection object from `connect()` and the host name to send a 'sh arp' command to each router and get the arp-table. Once the arp-table is received, the table is split by line and the IPs and Mac-addresses are extracted using regex.
The following information from each router is gathered and is added into a list of dictionaries per location:
-IPs, -Mac-Addresses, -Device Types (from `deviceType()`), -Vendors (from `getOuiVendor()`), -Hostnames (from `getHostnames()`), -Asset tags (from `assetTagGenerator()`). 
`getRouterInfo()` excludes duplicate and irrelevant hosts as the arp table is parsed.

`writeToFiles()` writes output from each location in both .csv json formats.

`getDeviceType()` Uses company pre-defined network configurations based on IP adresses to determine what kind of devices each host is. Devices can be Routers, Switches, Printers, Computers, Phones, etc.

`getOuiVendor()` Using [netaddr](https://github.com/drkjam/netaddr) each devices OUI, 

