import pymongo
import requests
from logging import FileHandler, Formatter, StreamHandler, getLogger, INFO
from json import decoder
from datetime import date
from lib import config as cfg


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
        logger.info('snipe db updated')

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

    except (KeyError,
            decoder.JSONDecodeError):
        content = None
        logger.exception('No response')
        return content
