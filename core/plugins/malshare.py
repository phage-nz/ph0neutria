#!/usr/bin/python3

from core.class_utils import MalwareUrl
from core.config_utils import get_base_config
from core.dns_utils import resolve_dns
from core.log_utils import get_module_logger
from core.string_utils import clean_url, get_host_from_url


import os
import re
import requests
import sys
import time


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TYPES = ['malware-url']
NAME = 'MalShare'
DISABLED = False


API_KEY = 'YOUR API KEY'


def get_malwareurl_list():
    """Produce a list of malware URLs from the MalShare feed.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    try:
        payload = {
            'action': 'getsourcesraw',
            'api_key': API_KEY}
        user_agent = {'User-agent': BASECONFIG.user_agent}

        LOGGING.info('Fetching latest MalShare list...')

        request = requests.get(
            'http://malshare.com/api.php',
            params=payload,
            headers=user_agent)

        if request.status_code == 200:
            LOGGING.info('Processing MalShare list...')

            url_list = []

            for line in request.text.split('\n'):
                url = clean_url(line.strip())

                if url is None or len(url) == 0:
                    continue

                host_name = get_host_from_url(url)
                ip_addr = resolve_dns(host_name)

                if ip_addr:
                    LOGGING.info('Discovered malicious URL: {0}'.format(url))

                    url_list.append(
                        MalwareUrl(
                            host_name,
                            ip_addr,
                            url,
                            'Malshare'))

            return url_list

        else:
            LOGGING.error(
                'Problem connecting to MalShare. Status code:{0}. Please try again later.'.format(
                    request.status_code))

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning('Problem connecting to Malshare. Error: {0}'.format(e))

    except Exception as e:
        LOGGING.warning('Problem connecting to Malshare. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return []
