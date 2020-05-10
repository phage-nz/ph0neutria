#!/usr/bin/python3

from __future__ import division
from core.config_utils import get_base_config
from datetime import date, timedelta
from core.log_utils import get_module_logger
from core.virus_total import get_urls_for_ip
from requests_toolbelt.multipart.encoder import MultipartEncoder


import json
import math
import os
import requests
import shodan
import sys
import time


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TYPES = ['malware-url']
NAME = 'Shodan'
DISABLED = False


API_KEY = 'YOUR API KEY'


def get_malwareurl_list():
    """Query Shodan for C2 servers hosting malware.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    api = shodan.Shodan(API_KEY)

    try:
        LOGGING.info('Querying Shodan for C2 servers...')

        limit_date = (
            date.today() -
            timedelta(
                days=BASECONFIG.malware_days)).strftime('%d/%m/%Y')
        search_term = 'category:malware after:{0}'.format(limit_date)

        results = api.search(search_term, page=1)

        LOGGING.info('Waiting a second...')
        time.sleep(1)

        results_num = int(results['total'])
        LOGGING.info('Results found: {0}'.format(str(results_num)))

        pages = int(math.ceil(results_num / 100))

        if pages > 0:
            url_list = []

            for n in range(1, pages + 1):
                if n > 1:
                    results = api.search(search_term, page=n)

                LOGGING.info('Fetched page {0} of {1}...'.format(n, pages))

                for result in results['matches']:
                    ip_list = get_urls_for_ip(result['ip_str'], NAME)

                    if len(ip_list) > 0:
                        url_list.extend(ip_list)

            return url_list

        else:
            return []

    except shodan.APIError as e:
        LOGGING.info('Error: {0}'.format(e))

    except Exception as e:
        LOGGING.info('Error: {0}'.format(e))

    return []
