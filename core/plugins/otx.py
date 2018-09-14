#!/usr/bin/python3

from core.class_utils import MalwareUrl
from core.config_utils import get_base_config
from core.dns_utils import resolve_dns
from core.log_utils import get_module_logger
from core.string_utils import clean_url, get_host_from_url
from core.virus_total import get_urls_for_ip
from datetime import datetime, timedelta
from OTXv2 import IndicatorTypes, OTXv2


import dateutil.parser
import os
import requests
import sys
import time
import validators


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TYPES = ['malware-url']
NAME = 'AlienVault OTX'
DISABLED = False


API_KEY = 'YOUR API KEY'
STALE_DAYS = 30


def get_otx_data():
    """Produce a list of IP addresses, domains and URLs from the OTX feed.

    Returns:
    - ip_list: (type: string list) list of IP addresses.
    - domain_list: (type: string list) list of domains.
    - url_list: (type: string list) list of URLs.
    """
    try:
        LOGGING.info('Querying AlienVault OTX for recent pulses...')

        otx = OTXv2(API_KEY)

        pulses = otx.getsince(
            (datetime.utcnow() -
             timedelta(
                days=BASECONFIG.malware_days)).isoformat(),
            limit=None)

        stale_days = STALE_DAYS
        stale_since = (datetime.utcnow() - timedelta(days=stale_days))

        domain_list = []
        ip_list = []
        url_list = []

        LOGGING.info('Processing OTX pulses...')

        for pulse in pulses:
            if dateutil.parser.parse(pulse['created']) < stale_since:
                LOGGING.warning('Pulse added more than {0} days ago: {1} ({2})'.format(
                    str(STALE_DAYS), pulse['name'], pulse['id']))
                continue

            indicators = pulse['indicators']

            if len(indicators) > 0:
                for indicator in indicators:
                    if indicator['type'] == 'URL':
                        url = clean_url(indicator['indicator'])

                        if url is None:
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
                                    'OTX'))

                    host_indicators = ['domain', 'hostname', 'IPv4']

                    if indicator['type'] in host_indicators:
                        if validators.ipv4(indicator['indicator']):
                            ip_list.append(indicator['indicator'])

                        else:
                            host_name = indicator['indicator']
                            domain_list.append(host_name)

        return ip_list, domain_list, url_list

    except Exception as e:
        LOGGING.warning('Problem connecting to Cymon. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return [], [], []


def get_malwareurl_list():
    """Produce a list of malware URLs from the OTX feed.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    try:
        ip_list, domain_list, url_list = get_otx_data()

        if len(domain_list) > 0:
            host_list = []

            for domain in domain_list:
                ip_addr = resolve_dns(domain)

                if ip_addr:
                    if ip_addr not in host_list:
                        host_list.append(ip_addr)
                        domain_urls = get_urls_for_ip(ip_addr, 'OTX')

                        if len(domain_urls) > 0:
                            url_list.extend(domain_urls)

        else:
            LOGGING.warning('OTX URL list (via domain) is empty.')

        if len(ip_list) > 0:
            for ip_addr in ip_list:
                ip_results = get_urls_for_ip(ip_addr, 'OTX')

                if len(ip_results) > 0:
                    url_list.extend(ip_results)

        else:
            LOGGING.warning('OTX URL list (via IP) is empty.')

        return url_list

    except Exception as e:
        LOGGING.warning('Problem connecting to Cymon. Aborting task.')
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return []
