import inventory
from lib.ips import get_ips
from re import compile
import random
# import unittest
# from lib import config as cfg
# import inv

# tests for ips.py
# tests for length of get_ips() to make sure ips are retrieved from snmpwalk
# tests to make sure at least 400 ips are retrieved
# tests to make sure ips are in x.x.x.x/mask format


mac_regex = compile(r'^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$')
ip_w_mask = compile(r'^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$')
ip_regex = compile(r'(?:\d+\.){3}\d+')


class TestIP:
    """Test class for IPs"""
    ip_list = get_ips()
    random_ip = random.choice(ip_list)

    def test_1():
        assert len(TestIP.ip_list) > 200

    def test_2():
        for item in TestIP.ip_list:
            re_value = ip_w_mask.search(item)
            assert re_value is not None

    def test_3():
        ip_value = ip_regex.search(TestIP.random_ip)
        assert ip_value is not None


class TestInventory:
    """Test class for Inventory"""

    # tests for inventory.py
    def test_1():
        assert inventory.connect(TestIP.random_ip) is not None

    def test_2():
        assert len(TestIP.results) > 0
        assert TestIP.results[0]['IP'] == TestIP.random_ip

        mac_value = mac_regex.search(TestIP.results[0]['Mac Address'])
        assert mac_value is not None

    # def test3():
    #   assert random.choice(results)['Model Name'] in cfg.models

    def test_4():
        conn = inventory.connect(TestIP.random_ip)
        print(conn)
        TestIP.results = inventory.get_router_info(conn,
                                                   TestIP.random_ip,
                                                   device_type='fortinet',
                                                   loc_id_data=None)
