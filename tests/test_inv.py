from re import compile
import random
from Inventory import config as cfg
from Inventory import ips
from Inventory import inventory

# tests for ips.py
# tests for length of get_ips() to make sure ips are retrieved from snmpwalk
# tests to make sure at least 400 ips are retrieved
# tests to make sure ips are in x.x.x.x/mask format

ip_list = ips.get_ips()
random_ip = random.choice(ip_list)
random_ip_router = str(inventory.get_site_router(random_ip))

mac_regex = compile(r'^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$')
ip_w_mask = compile(r'^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$')
ip_regex = compile(r'(?:\d+\.){3}\d+')

results = []
results = inventory.get_router_info(inventory.connect(random_ip_router),
                                    random_ip_router)


def test1_ips():
    assert len(ip_list) > 200


def test2_ips():
    for item in ip_list:
        re_value = ip_w_mask.search(item)
        assert re_value is not None


def test3_ips():
    ip_value = ip_regex.search(random_ip_router)
    assert ip_value is not None


# tests for inventory.py
def test1_inv():
    assert inventory.connect(random_ip_router) is not None


def test2_inv():
    assert len(results) > 0
    assert results[0]['IP'] == random_ip_router

    mac_value = mac_regex.search(results[0]['Mac Address'])
    assert mac_value is not None


#def test3_inv():
 #   assert random.choice(results)['Model Name'] in cfg.models
