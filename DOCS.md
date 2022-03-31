# Asset Inventory Script Documentation
<h2>Inventory.py</h2>
<h3>Functions</h3>
**main
main function to run script, scans all clubs using
    get_ip_list from ips.py or using a specific list of ips from args

    Args:
        ip_list

    Returns:
        None
This function uses concurrent futures with 20 consecutive threads, and iterates through the ip list, scanning each ip and getting all devices connected to each ip(router)


**club_scan

function to scan each club using club ip

This is the function that makes it all happen, calling all the helper functions, listed below.
    Args:
        ip for each location

    Returns:
        Info for assets that need to be added or removed

    Raises:
        Does not raise an error.
        Returns None if club cannot be scanned

-Variables:
    add_diff - list of all items that are different from prior scan
    all_api_payload - all items 
    add - all items that need to be added (per club)
    remove - all items that need to be removed (per club)
    connect_obj - connect object returned from connect()
    scan_count - number of clubs scanned, used for reporting

connect() returns the connect object and the device type(whether it is cisco or fortigate, this will be removed soon once cisco is no longer a thing).
The connect object from connect() is sent to the function get_router_info() with the device_type, ip and location_ids (from snipe-it)

`connect()` Uses ConnectHandler from [netmiko](https://github.com/ktbyers/netmiko) to connect to each location's router via SSH. It attempts to connect twice before it quits and returns `None` if a connection could not be made. Returns a connection object used in `club_scan()`

**scan_started - Helper function to update global scan_count variable tokeep track of locations scanned.

**get_router_info - Sends command to each router to retrieve its arp-table, extracting all devices' mac-addresses and combines this with additional device information in a list of dictionaries per location.
Returns list of dictionaries with each asset's information:

Example output per device:
        {'IP': 'x.x.x.x',
         'Location': '',
         'Asset Tag': '000P-ABCD-000-000',
         'Category': 'Phone',
         'Manufacturer': 'Cisco',
         'Hostname': 'name@name.com',
         'Mac Address': 'XX:XX:XX:XX:XX:XX',
         'Status': 'up'}

If router information cannot be retrieved, a dictionary containing the host, club and status is appended to a list of failed results for investigation.


**save_results - Function to add results to .json and .csv files, saved by location
These files are used for record keeping in addition to mongodb database. (May get removed in next version)
**add_to_db - Add results for each club results in mongodb, in inventory collection by date.

**csv - Save full scans by date (all clubs). This is used in get_diff() to find if asset has been found in previous 4 scans to decide whether or not to delete or add.

**csv_trunc - overwriting to avoid duplicates if a scan is run more than once in a day

**check_if_remove - This function checks the files from last_4_baselines(), to check if that device was found in the past 4 weeks (4 last scans). If the asset was found, it returns False, otherwise it returns True. This is used in mongo_diff() to decide whether to remove an item from snipe-it and mongo-db.

**check_if_add - This function checks the files from last_4_baselines(), to check if that device was found in the past 4 weeks (4 last scans). If the asset was found, it returns False, otherwise it returns True. This is used in mongo_diff() to decide whether to add or restore an item from snipe-it and mongo-db.
**mongo_diff
**api_payload
**api_call
**get_id
**last_4_baselines
**club_id
**get_hostnames
** club_num
**asset_tag_gen
**get_club_ips
**get_club
**club_ips
**inv_args
**script_info

<h3>Variables</h3>
**not_connected
**not_scanned
**clubs
**additional_ids

**restored
**added
**deleted
**scan_count
**scan_queue
**club_quwuw
**api_status
**location_ids

<h2>ips.py</h2>
<h3>Functions</h3>
**get_ips

<h2>get_snipe_inv.py</h2>
<h3>Functions</h3>
**get_snipe
**get_loc_id

<h2>ipsinv_mail.py</h2>
<h3>Functions</h3>
**send_mail

*-IP Address*
*-Location*
*-Asset Tag*
*-Device Type*
*-Vendor*
*-Hostname*
*-Mac Address*
*-Status*


How it works:

***ips.py:***

`get_ips():`
Uses [Session](https://github.com/kamakazikamikaze/easysnmp/blob/master/easysnmp/session.py) from [easysnmp](https://github.com/kamakazikamikaze/easysnmp) to connect to the main router and perform an SNMPWalk. Using specific OIDs, IP and mask information is extracted using regex and added to a list with values combined in ip/subnet_mask format (CIDR notation).

`always_exclude():`
Creates list of excluded IPs that do not need to be included in final IP list in X.X.X.0 format

`exclude():`
Returns list of excluded IPs from specific OID values

`get_ip_list():`
Returns final IP list by removing exclude_list from ip_list in X.X.X.0/mask format


***inventory.py***


`getRouterInfo` Uses connection object from `connect()` and the host name to send a 'sh arp' command to each router and get the arp-table. Once the arp-table is received, the table is split by line and the IPs and Mac-addresses are extracted using regex.
The following information from each router is gathered and is added into a list of dictionaries per location:
-IPs, -Mac-Addresses, -Device Types (from `deviceType()`), -Vendors (from `getOuiVendor()`), -Hostnames (from `getHostnames()`), -Asset tags (from `assetTagGenerator()`).
`getRouterInfo()` excludes duplicate and irrelevant hosts as the arp table is parsed.

`writeToFiles()` writes/appends output from each location in both .csv & .json formats.

`getDeviceType()` Uses company pre-defined network configurations based on IP adresses to determine what kind of devices each host is. Devices can be Routers, Switches, Printers, Computers, Phones, etc.

`getOuiVendor()` Using EUI from [netaddr](https://github.com/drkjam/netaddr) each device's OUI is retrieved from ieee.org. There are some OUIs that are not found, so they are added in the config file for use in this function.

`macAddressFormat()` Using EUI and mac_unix_expanded from [netaddr](https://github.com/drkjam/netaddr), returns formatted version of a mac address to format: XX:XX:XX:XX:XX:XX.

`clubID()` Using [netmiko](https://github.com/drkjam/netaddr) to create a connection object from `connect()` and sends a 'sh cdp entry \*' command to each router to retrieve the location ID. Regex is then used to extract said ID and returned for use in `getRouterInfo()`.

`getHostnames()` Uses [python-nmap](https://pypi.org/project/python-nmap/) to scan each host and retrieve the hostname and status to be used in `getRouterInfo()`.

`assetTagGenerator()` Returns a generated asset tag for the host based on the location ID, Initial of type of device, Mac-address last 4, and IP last 2 octets.

`main()` Takes each IP address from ***ips.py*** to connect, get router's information write to files and disconnect, it loops through all locations, writes to files and returns a list of successful and unsuccessful hosts for troubleshooting.
