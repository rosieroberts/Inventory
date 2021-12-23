#!/usr/bin/env python3

import pytest
import Inventory.inventory
from lib.ips import get_ips
from lib.get_snipe_inv import get_snipe, get_loc_id
from lib.inv_mail import send_mail
from re import compile
from datetime import date
from time import time, ctime
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
file_handler = FileHandler('/opt/Inventory/logs/tests{}.log'
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
    results = Inventory.inventory.club_scan(random_ip)
    return results


@pytest.fixture
def results_0(random_ip, results):
    res = results[0]
    return res


@pytest.fixture
def get_sn():
    all_items, entries = get_snipe()
    return all_items, entries


@pytest.fixture
def loc_id():
    loc_id = get_loc_id()
    return loc_id


@pytest.fixture
def mail():
    start = time()
    end = time()
    runtime = end - start
    clubs = ['club001', 'club002']
    club_queue = ['club003', 'club004']
    scan_queue = ['8.8.8.8', '0.0.0.0']
    not_scanned = ['club005']
    api_status = [{'asset_tag': '062H-FBE6',
                   'status': 'success'},
                  {'asset_tag': '062H-FBAA',
                   'status': 'error'}]
    added = [('club006', '062H-FB88')]
    restored = []
    deleted = []
    msg = send_mail(ctime(start),
                    runtime,
                    clubs,
                    club_queue,
                    scan_queue,
                    not_scanned,
                    api_status,
                    added,
                    restored,
                    deleted)
    return msg


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

    res = results_0

    # tests for inventory.py
    def test_1(self, results):
        assert results is not None

    def test_2(self, results):
        assert len(results) > 0


class TestGetSnipe:
    """Test class for get_snipe"""

    def test_1(self, get_sn):
        all_entries, entries = get_sn
        assert len(all_entries) > 0
        assert entries == True

    def test_2(self, loc_id, results_0):
        # loc_id list of clubs location IDs
        location_id = False
        assert loc_id is not None
        location = results_0['Location']
        for itm in loc_id['rows']:
            if itm['name'] == str(location):
                loc_i = itm['id']
                location_id = True
        assert location_id == True
        assert type(loc_i) == int


class TestInvMail:
    """Test for mail_inv"""

    def test_1(self, mail):
        msg = mail
        assert mail is not None
        # assert type(msg) is "<class 'email.message.EmailMessage'>"


if __name__ == '__main__':
    pytest.main()
