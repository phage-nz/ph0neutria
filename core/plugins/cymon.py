#!/usr/bin/python3

from __future__ import division
from core.class_utils import MalwareUrl
from core.config_utils import get_base_config
from datetime import datetime, timedelta
from core.dns_utils import resolve_dns
from core.log_utils import get_module_logger
from core.virus_total import get_urls_for_ip


import dateutil.parser
import json
import math
import os
import requests
import sys
import time


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TYPES = ['malware-url']
NAME = 'Cymon'
DISABLED = False


CYMON_USER = 'YOUR USERNAME'
CYMON_PASS = 'YOUR PASSWORD'
BATCH_SIZE = 100

# AVsGgRbdVjrVcoBZyoid: Abuse.ch Ransomware Tracker  
# AVsGgNL4VjrVcoBZyoib: Abuse.ch Zeus Tracker  
# AVvtZm8i2c0QRQctzx4f: Bambenek Consulting C2  
# AVsIOKQlVjrVcoBZyojw: Cyber Crime Tracker  
# AVsGX4iNVjrVcoBZyoiH: Malc0de  
# AVsGXy7tVjrVcoBZyoiB: URLVir  
# AVsGgHxAVjrVcoBZyoiX: VX Vault  

FEED_LIST = ['AVsGgRbdVjrVcoBZyoid', 'AVsGgNL4VjrVcoBZyoib', 'AVvtZm8i2c0QRQctzx4f', 'AVsGX4iNVjrVcoBZyoiH', 'AVsGXy7tVjrVcoBZyoiB', 'AVsGgHxAVjrVcoBZyoiX']


def cymon_auth():
    """Authenticate against the Cymon API.

    Returns:
    - result: (type: string) Cymon JWT token.
    """
    try:
        payload = {
            'username': CYMON_USER,
            'password': CYMON_PASS}
        headers = {'Content-Type': 'application/json'}

        LOGGING.info('Authenticating against Cymon API...')

        request = requests.post(
            'https://api.cymon.io/v2/auth/login',
            data=json.dumps(payload),
            headers=headers,
            verify=False)

        if request.status_code == 200:
            LOGGING.info('Authentication successful!')

            return json.loads(request.text)['jwt']

        else:
            LOGGING.error(
                'Problem connecting to Cymon. Status code:{0}. Please try again later.'.format(
                    request.status_code))

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning('Problem connecting to Cymon. Error: {0}'.format(e))

    except Exception as e:
        LOGGING.warning('Problem connecting to Cymon. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return False


def get_cymon_feed_size(jwt, feed_id):
    """Determine the number of results a feed will return (max: 1000).

    Params:
    - jwt: (type: string) JWT token.
    - feed_id: (type: string) Cymon feed ID.

    Returns:
    - total: (type: int) feed size.
    """
    try:
        today = datetime.utcnow()
        threshold = today - timedelta(days=BASECONFIG.malware_days)

        headers = {'Authorization': 'Bearer {0}'.format(jwt)}
        payload = {
            'startDate': threshold.strftime('%Y-%m-%d'),
            'endDate': today.strftime('%Y-%m-%d'),
            'size': 1}

        LOGGING.info('Determining feed size...')

        request = requests.get(
            'https://api.cymon.io/v2/ioc/search/feed/{0}'.format(feed_id),
            params=payload,
            headers=headers,
            verify=False)

        if request.status_code == 200:
            LOGGING.info('Request successful!')
            response = json.loads(request.text)

            if 'total' in response:
                total = int(response['total'])

                if total > 1000:
                    LOGGING.warning(
                        'API request returned more than 1000 results.')
                    total = 1000

                return total

        else:
            LOGGING.error(
                'Problem connecting to Cymon. Status code:{0}. Please try again later.'.format(
                    request.status_code))

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning('Problem connecting to Cymon. Error: {0}'.format(e))

    except Exception as e:
        LOGGING.warning('Problem connecting to Cymon. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return 0


def get_cymon_feed(jwt, feed_id, pages):
    """Produce a list of URLs for IPs found in the feed.

    Params:
    - jwt: (type: string) JWT token.
    - feed_id: (type: string) Cymon feed ID.
    - pages: (type: int) number of pages to retrieve.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    try:
        today = datetime.utcnow()
        threshold = today - timedelta(days=BASECONFIG.malware_days)

        headers = {'Authorization': 'Bearer {0}'.format(jwt)}

        LOGGING.info('Fetching data from Cymon feed: {0}'.format(feed_id))

        ip_list = []

        for n in range(1, pages + 1):
            payload = {
                'startDate': threshold.strftime('%Y-%m-%d'),
                'endDate': today.strftime('%Y-%m-%d'),
                'size': BATCH_SIZE,
                'from': (
                    BATCH_SIZE *
                    n -
                    BATCH_SIZE)}

            request = requests.get(
                'https://api.cymon.io/v2/ioc/search/feed/{0}'.format(feed_id),
                params=payload,
                headers=headers,
                verify=False)

            if request.status_code == 200:
                LOGGING.info('Request successful!')

                response = json.loads(request.text)

                if 'hits' in response:
                    for feed_entry in response['hits']:
                        if 'ioc' in feed_entry:
                            if 'ip' in feed_entry['ioc']:
                                mal_ip = feed_entry['ioc']['ip']

                                if mal_ip not in ip_list:
                                    ip_list.append(mal_ip)

                                elif 'hostname' in feed_entry['ioc']:
                                    host_name = feed_entry['ioc']['hostname']
                                    mal_ip = resolve_dns(host_name)

                                    if mal_ip:
                                        if mal_ip not in ip_list:
                                            ip_list.append(mal_ip)

            else:
                LOGGING.error(
                    'Problem connecting to Cymon. Status code:{0}. Please try again later.'.format(
                        request.status_code))

        if len(ip_list) > 0:
            url_list = []

            for ip_addr in ip_list:
                ip_results = get_urls_for_ip(ip_addr, 'Cymon')

                if len(ip_results) > 0:
                    url_list.extend(ip_results)

            return url_list

        else:
            LOGGING.warning('No hosts of interest.')

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning('Problem connecting to Cymon. Error: {0}'.format(e))

    except Exception as e:
        LOGGING.warning('Problem connecting to Cymon. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return []


def get_malwareurl_list():
    """Produce a list of malware URLs from Cymon feeds.

    Returns:
    - return_list: (type: MalwareUrl list) list of malware URLs.
    """
    jwt = cymon_auth()

    if jwt:
        return_list = []

        for feed in FEED_LIST:
            LOGGING.info('Processing feed: {0}'.format(feed))

            feed_size = get_cymon_feed_size(jwt, feed)

            if feed_size > 0:
                pages = int(math.ceil(feed_size / BATCH_SIZE))

                if pages < 1:
                    pages = 1

                url_list = get_cymon_feed(jwt, feed, pages)

                if len(url_list) > 0:
                    return_list.extend(url_list)

        return return_list

    else:
        LOGGING.warning('No Cymon authentication token. Cannot query API.')

    return []
