#!/usr/bin/env python3

import pytest
import inventory
from lib.ips import get_ips
from re import compile
from datetime import date
import random
from logging import (
    FileHandler,
    Formatter,
    StreamHandler,
    getLogger,
    DEBUG)
# import unittest
# from lib import config as cfg
# import inv

# tests for ips.py
# tests for length of get_ips() to make sure ips are retrieved from snmpwalk
# tests to make sure at least 400 ips are retrieved
# tests to make sure ips are in x.x.x.x/mask format

today = date.today()

# logging set up
logger = getLogger(__name__)

file_formatter = Formatter('{asctime} {threadName}: {message}', style='{')
stream_formatter = Formatter('{threadName} {message}', style='{')

# logfile
file_handler = FileHandler('/opt/Inventory/logs/asset_inventory{}.log'
                           .format(today.strftime('%m%d%Y')))
file_handler.setLevel(DEBUG)
file_handler.setFormatter(file_formatter)

# console
stream_handler = StreamHandler()
stream_handler.setFormatter(stream_formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

mac_regex = compile(r'^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$')
ip_regex = compile(r'(?:\d+\.){3}\d+')


@pytest.fixture(autouse=True)
def ips():
    ip_list = get_ips()
    return ip_list


@pytest.fixture
def random_ip(ips):
    random_ip = random.choice(ips)
    return random_ip


@pytest.fixture
def results(random_ip):
    results = inventory.club_scan(random_ip)
    print(results)
    return results


@pytest.fixture
def ran_results(random_ip, results):
    res = random.choice(results)
    print(res)
    return res


class TestIP:
    """Test class for IPs"""

    def test_1(self, ips):
        logger.debug('len ip_list ', len(ips) > 200)
        assert len(ips) > 200

    def test_2(self, ips):
        for item in ips:
            re_value = ip_regex.search(item)
            logger.debug(re_value)
            assert re_value is not None

    def test_3(self, random_ip):
        ip_value = ip_regex.search(random_ip)
        assert ip_value is not None


class TestInventory:
    """Test class for Inventory"""

    res = ran_results

    # tests for inventory.py
    def test_1(self, results):
        assert results is not None

    def test_2(self, results):
        assert len(results) > 0


if __name__ == '__main__':
    pytest.main()
