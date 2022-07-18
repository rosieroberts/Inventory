import pymongo
import requests
from logging import FileHandler, Formatter, StreamHandler, getLogger, INFO
from json import decoder
from datetime import date
from lib import config as cfg
from time import sleep


logger = getLogger('get_snipe')
# TODO: set to ERROR later on after setup
logger.setLevel(INFO)

file_formatter = Formatter('{asctime} {name} {levelname}: {message}', style='{')
stream_formatter = Formatter('{message}', style='{')
today = date.today()

# logfile
file_handler = FileHandler('/opt/Inventory/logs/asset_inventory{}.log'
                           .format(today.strftime('%m%d%Y')))
file_handler.setLevel(INFO)
file_handler.setFormatter(file_formatter)

# console
stream_handler = StreamHandler()
stream_handler.setFormatter(stream_formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)


def get_snipe():
    """Returns all current information for each host.
    this function returns SNIPE-IT's current device information
    this device information will be used to have a snapshot of
    the devices already in snipe-it.

    Args:
        None

    Returns:
        Everything from snipe-it. still working this out

    """

    try:
        all_items = []
        url = cfg.api_url_get_all
        response = requests.request("GET", url=url, headers=cfg.api_headers)
        content = response.json()
        total_record = content['total']

        if total_record == 0:
            logger.info('No data in Snipe-IT')
            content = None
            return content

        for offset in range(0, total_record, 500):
            querystring = {"offset": offset}
            response = requests.request("GET",
                                        url=url,
                                        headers=cfg.api_headers,
                                        params=querystring)
            content = response.json()
            for item in content['rows']:
                device = {'ID': item['id'],
                          'Asset Tag': item['asset_tag'],
                          'IP': item['custom_fields']['IP']['value'],
                          'Mac Address': item['custom_fields']['Mac Address']['value'],
                          'Location': item['location']['name'],
                          'Location ID': item['rtd_location']['id'],
                          'Category': item['category']['name'],
                          'Hostname': item['custom_fields']['Hostname']['value'],
                          'Manufacturer': item['manufacturer']['name'],
                          'Model Name': item['model']['name']}
                all_items.append(device)

        # print(*all_items, sep='\n')

        myclient = pymongo.MongoClient("mongodb://localhost:27017/")

        # use database named "inventory"
        mydb = myclient['inventory']

        # use collection named "snipe"
        mycol = mydb['snipe']

        # delete prior scan items
        if mycol.count() > 0:
            mycol.delete_many({})

        # insert list of dictionaries
        mycol.insert_many(all_items)
        logger.debug('snipe db updated')

        full_club_list = mycol.find({'Category': 'Router'},
                                    {'Location': 1,
                                     'IP': 1,
                                     '_id': 0})

        club_list = []
        for item in full_club_list:
            club_list.append(item)

        # use collection 'club_list'
        club_list_coll = mydb['club_list']

        # delete prior scan items
        club_list_coll.delete_many({})

        # insert full club list into mongodb collection
        club_list_coll.insert_many(club_list)

        num_entries = mycol.count()
        entries = False

        if num_entries:
            entries = True

        return (all_items, entries)

    except (KeyError,
            decoder.JSONDecodeError):
        content = None
        logger.exception('No response')
        return content


def get_loc_id():
    """Get Location IDs from all clubs, needed to run script"""
    for attempt in range(3):
        try:
            url_loc = cfg.api_url_get_locations
            response_loc = requests.request("GET",
                                            url=url_loc,
                                            headers=cfg.api_headers)
            loc_id_data = response_loc.json()
            if loc_id_data:
                break
        except decoder.JSONDecodeError:
            loc_id_data = None
            if attempt == 2:
                logger.exception('Cannot get location information from API. '
                                 'Stopping Script')
                exit()
            else:
                continue

    return loc_id_data


def check_in(snipe_list):
    # check in seats for each asset in list of snipe assets
    # use this when deleting an item from snipe it.
    id_list = []

    if snipe_list is None:
        logger.info('No asset to check in seats for')
        return None

    if type(snipe_list) != list:
        snipe_list = [snipe_list]

    for item in snipe_list:
        # get asset ids for each asset and append to id_list
        asset_id = item['ID']
        id_list.append(asset_id)

    client = pymongo.MongoClient("mongodb://localhost:27017/")
    software_db = client['software_inventory']

    # Snipe Seats collection
    snipe_seats = software_db['snipe_seat']
    # this list contains one item for normal run, but also may contain several assets
    # for checking in licenses for several assets

    for id_ in id_list:
        not_succ = 0
        # for each asset in list
        seats = snipe_seats.find({'assigned_asset': id_},
                                 {'id': 1, 'license_id': 1, 'asset_name': 1, '_id': 0})

        seats = list(seats)
        if len(seats) == 0:
            logger.info('No seats found to check in for asset id {}'.format(id_))
            if len(id_list) > 1:
                continue
            else:
                return False

        for count, seat in enumerate(seats):
            # for each seat checked out to asset
            license_id = seat['license_id']
            seat_id = seat['id']
            not_successful = 0

            # license ID and seat id
            url = cfg.api_url_software_seat.format(license_id, seat_id)
            sleep(5)
            item_str = str({'asset_id': ''})
            payload = item_str.replace('\'', '\"')
            response = requests.request("PATCH",
                                        url=url,
                                        data=payload,
                                        headers=cfg.api_headers)
            logger.info(response.text)
            status_code = response.status_code

            if status_code == 200:
                content = response.json()
                status = str(content['status'])
                if status == 'success':
                    logger.info('Successfully checked in seat for license {} for asset id {}'.format(seat['license_id'], id_))
                else:
                    logger.info('Could not check in seat for license {} for asset id {}'.format(seat['license_id'], id_))
                    not_successful += 1
            else:
                logger.info('Could not check in seat for license {} for asset id {}, error'.format(seat['license_id'], id_))
                not_successful += 1

        if not_successful != 0:
            not_succ += 1

    if not_succ != 0:
        logger.info('Not all seats could be checked in')
        return False

    else:
        logger.info('All seats for all assets supplied have been checked in')
        return True
