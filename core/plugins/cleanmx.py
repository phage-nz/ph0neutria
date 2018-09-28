#!/usr/bin/python3

from core.class_utils import MalwareUrl
from core.config_utils import get_base_config
from datetime import datetime, timedelta, timezone
from core.log_utils import get_module_logger
from core.string_utils import clean_url, get_host_from_url


import dateutil.parser
import feedparser
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
NAME = 'CleanMX'
DISABLED = False


USER_AGENT = 'YOUR USER AGENT'


def get_malwareurl_list():
    """Produce a list of malware URLs from the CleanMX virus feed.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    try:
        url_list = []

        LOGGING.info('Fetching Clean MX virus data...')

        feedparser.USER_AGENT = USER_AGENT
        feed = feedparser.parse(
            'http://support.clean-mx.com/clean-mx/rss?scope=viruses')
        feed_entries = feed.entries

        LOGGING.info('Clean MX request OK.')

        valid_since = datetime.now(tz=timezone.utc) - timedelta(days=BASECONFIG.malware_days)

        for entry in feed_entries:
            if not hasattr(entry, 'published'):
                LOGGING.warning('Encountered incomplete entry in feed.')
                continue

            date = dateutil.parser.parse(entry.published)

            if date > valid_since:
                entry_data = entry.description.strip()

                url_search = re.search(r'url:\t(.*?)<br />', entry_data)
                addr_search = re.search(
                    r'ip:\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<br />', entry_data)

                if bool(url_search):
                    url = clean_url(url_search.group(1))

                    if url is None:
                        continue

                    host_name = get_host_from_url(url)

                else:
                    LOGGING.warning('Encountered invalid line in feed.')
                    continue

                if bool(addr_search):
                    ip_addr = addr_search.group(1)

                else:
                    LOGGING.warning('Encountered invalid line in feed.')
                    continue

                LOGGING.info('Discovered malicious URL: {0}'.format(url))

                url_list.append(
                    MalwareUrl(
                        host_name,
                        ip_addr,
                        url,
                        'Clean MX'))

            else:
                break

        return url_list

    except Exception as e:
        LOGGING.warning('Problem connecting to Clean MX. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return []
