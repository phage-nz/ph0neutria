#!/usr/bin/python3

from __future__ import division
from core.class_utils import MalwareUrl
from core.config_utils import get_base_config
from datetime import datetime, timedelta
from core.dns_utils import resolve_dns
from core.log_utils import get_module_logger
from core.string_utils import clean_url, get_host_from_url


import csv
import dateutil.parser
import json
import os
import requests
import sys
import time


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TYPES = ['malware-url']
NAME = 'URLhaus'
DISABLED = False


def get_malwareurl_list():
    """Produce a list of malware URLs from the URLhaus feed.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    try:
        user_agent = {'User-agent': BASECONFIG.user_agent}

        LOGGING.info('Fetching latest URLhaus list...')

        request = requests.get(
            'https://urlhaus.abuse.ch/downloads/csv/',
            headers=user_agent)

        if request.status_code == 200:
            LOGGING.info('Processing URLhaus list...')

            url_list = []

            lines = request.text.split('\n')

            for line in lines:
                if line.startswith('#'):
                    lines.remove(line)

            reader = csv.reader(
                lines,
                quotechar='"',
                delimiter=',',
                quoting=csv.QUOTE_ALL,
                skipinitialspace=True)
            next(reader)

            for item in reader:
                if len(item) > 1:
                    if item[3] == 'offline':
                        continue

                    url = clean_url(item[2])

                    if url is None or len(url) == 0:
                        continue

                    date = dateutil.parser.parse(item[1])

                    valid_since = datetime.now() - timedelta(days=BASECONFIG.malware_days)

                    if date > valid_since:
                        host_name = get_host_from_url(url)
                        ip_addr = resolve_dns(host_name)

                        if ip_addr:
                            LOGGING.info(
                                'Discovered malicious URL: {0}'.format(url))

                            url_list.append(
                                MalwareUrl(
                                    host_name,
                                    ip_addr,
                                    url,
                                    'URLhaus'))

                    else:
                        break

            return url_list

        else:
            LOGGING.error(
                'Problem connecting to URLhaus. Status code:{0}. Please try again later.'.format(
                    request.status_code))

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning('Problem connecting to URLhaus. Error: {0}'.format(e))

    except Exception as e:
        LOGGING.warning('Problem connecting to URLhaus. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return []
