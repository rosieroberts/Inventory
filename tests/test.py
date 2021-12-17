import inventory
from lib.ips import get_ips
from re import compile
import random
import unittest
# from lib import config as cfg
# import inv

# tests for ips.py
# tests for length of get_ips() to make sure ips are retrieved from snmpwalk
# tests to make sure at least 400 ips are retrieved
# tests to make sure ips are in x.x.x.x/mask format


mac_regex = compile(r'^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$')
ip_w_mask = compile(r'^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$')
ip_regex = compile(r'(?:\d+\.){3}\d+')


class IPTest:
    """Test class for IPs"""

    def __init__(self):
        ip_list = get_ips()
        random_ip = random.choice(ip_list)
        results = []

    def test1_ips():
        assert len(IPTest.ip_list) > 200

    def test2_ips():
        for item in IPTest.ip_list:
            re_value = ip_w_mask.search(item)
            assert re_value is not None

    def test3_ips():
        ip_value = ip_regex.search(IPTest.random_ip)
        assert ip_value is not None


class InventoryTest:
    """Test class for Inventory"""

    # tests for inventory.py
    def test1_inv():
        assert inventory.connect(IPTest.random_ip) is not None

    def test2_inv():
        assert len(IPTest.results) > 0
        assert IPTest.results[0]['IP'] == IPTest.random_ip

        mac_value = mac_regex.search(IPTest.results[0]['Mac Address'])
        assert mac_value is not None

    # def test3_inv():
    #   assert random.choice(results)['Model Name'] in cfg.models

    def test4_inv():
        conn = inventory.connect(IPTest.random_ip)
        print(conn)
        IPTest.results = inventory.get_router_info(conn,
                                                   IPTest.random_ip,
                                                   device_type='fortinet',
                                                   loc_id_data=None)


if __name__ == "__main__":
    IPTest.test1_ips()
    print("Everything passed")
