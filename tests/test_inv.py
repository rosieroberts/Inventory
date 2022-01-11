#!/usr/bin/env python3

import pytest
import Inventory.inventory as inv
from lib.ips import get_ips
from lib.get_snipe_inv import get_snipe, get_loc_id
from lib.inv_mail import send_mail
import lib.config as cfg
from re import compile
from datetime import date
from time import time, ctime
import random
import pymongo
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
    results = inv.club_scan(random_ip)
    return results


@pytest.fixture
def router_info(random_ip):
    connect = inv.connect(random_ip)
    connect_obj = connect[0]
    device_type = connect[1]
    info = inv.get_router_info(connect_obj,
                           str(random_ip),
                           device_type,
                           inv.location_ids)
    print(info)
    return info


@pytest.fixture
def get_ip_num(results):
    ip_res = []
    for item in results:
        club = results[0]['Location']
        ip = inv.get_club_ips(club)
        ip_res.append(ip)
    return ip_res


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
    clubs = cfg.clubs
    club_queue = cfg.club_queue
    scan_queue = cfg.scan_queue
    not_scanned = cfg.not_scanned
    api_status = cfg.api_status
    added = cfg.added
    restored = cfg.restored
    deleted = cfg.deleted
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


@pytest.fixture(autouse=True)
def mongo_loc(results):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client['inventory']
    snipe_coll = db['snipe']
    snipe_location = snipe_coll.find({'Location': results[0]['Location']},
                                     {'Location': 1, '_id': 0})
    return snipe_location


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

    def test_3(self, ips):
        for item in ips:
            assert item not in cfg.exclude_ips


class TestInventory:
    """Test class for Inventory

    # tests for inventory.py

    FUNCTIONS:

    # main
    club_scan
    # scan_started
    connect
    get_router_info
    # save_results
    # add_to_db
    # csv
    # csv_trunc
    # check_if_remove
    # check_if_add
    # mongo_diff
    # api_payload
    # api_call
    # get_id
    # last_4_baselines
    club_id
    # get_hostnames
    # club_num
    # asset_tag_gen
    get_club_ips
    # get_club
    # club_ips
    # inv_args
    # script_info
    """

    # club_scan
    def test_1(self, results):
        assert results is not None
        assert len(results) > 2


    # get_router_info 
    def test_2(self, router_info):
        info = router_info
        club_number = info[0]['Location']
        club_rgx = compile(cfg.club_rgx)
        for item in info:
            assert item['Location'] is club_number
            # assert cfg.club_rgx.match(item['Location']) is not None
            assert item['Status'] == 'up'
            assert ip_regex.match(item['IP']) is not None
            assert mac_regex.match(item['Mac Address']) is not None
            


    # get_club_ips
    def test_3(self, get_ip_num, random_ip):
        ips = get_ip_num
        assert random_ip in ips


    # test for each key in results from club_scan
    def test_4(self, results):
        for item in results:
            assert item['ID'] is not None
            assert item['Asset Tag'] is not None
            assert item['IP'] is not None
            assert item['Location'] is not None   
            assert item['Location ID'] is not None
            assert item['Category'] is not None
            assert item['Manufacturer'] is not None
            assert item['Model Name'] is not None
            assert item['Model Number'] is not None
            assert item['Mac Address'] is not None
            assert item['Status'] is not None
            assert item['Status ID'] is not None


    # connect
    def test_5(self):
        assert inv.connect is not None


    # mongo locations test
    def test_6(self, mongo_loc, results):
        assert results[0]['Location'] == mongo_loc[0]['Location']


class TestGetSnipe:
    """Test class for get_snipe"""

    def test_1(self, get_sn):
        all_entries, entries = get_sn
        assert len(all_entries) > 0
        assert entries is True

    def test_2(self, loc_id, results):
        # loc_id list of clubs location IDs
        location_id = False
        assert loc_id is not None
        location = results[0]['Location']
        for itm in loc_id['rows']:
            if itm['name'] == str(location):
                loc_i = itm['id']
                location_id = True
        assert location_id is True
        assert type(loc_i) == int


class TestInvMail:
    """Test for mail_inv"""

    def test_1(self, mail):
        assert mail is not None


if __name__ == '__main__':
    pytest.main()
