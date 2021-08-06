import pymongo
import requests
from json import decoder
import config as cfg


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

        for offset in range(0, total_record, 500):
            querystring = {"offset": offset}
            response = requests.request("GET", url=url, headers=cfg.api_headers, params=querystring)
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

        print(*all_items, sep='\n')

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

    except (KeyError,
            decoder.JSONDecodeError):
        content = None
        print('No response')
        return content
