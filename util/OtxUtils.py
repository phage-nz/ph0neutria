#!/usr/bin/python
from ConfigUtils import getBaseConfig
from datetime import datetime, timedelta
from LogUtils import getModuleLogger
from MachineUtils import getSignificantItems
from VirusTotal import getUrlsForDomain, getUrlsForIp
from OTXv2 import OTXv2
from StringUtils import isValidIP


import datetime
import json
import os
import string
import sys


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)


logging = getModuleLogger(__name__)


def getPulseData():
    logging.info('Querying AlienVault OTX for recent pulses...')

    otx = OTXv2(baseConfig.otxKey)

    days_back = int(baseConfig.osintDays) + 1
    date_since = (datetime.datetime.now() - datetime.timedelta(days=days_back)).isoformat()
    pulses = otx.getsince(date_since, limit=None)

    ip_list = []
    domain_list = []
    url_list = []

    for pulse in pulses:
        indicators = pulse['indicators']

        if len(indicators) > 0:
            for indicator in indicators:
                if indicator['type'] == 'URL':
                    url_list.append(indicator['indicator'])

                host_indicators = ['domain', 'hostname', 'IPv4']

                if indicator['type'] in host_indicators:
                    if isValidIP(indicator['indicator']):
                        ip_list.append(indicator['indicator'])

                    else:
                        domain_list.append(indicator['indicator'])

    return ip_list, domain_list, url_list


def getOTXList():
    ip_list, domain_list, pulse_url = getPulseData()

    url_list = []

    if len(pulse_url) > 0:
        url_list.extend(pulse_url)

    else:
        logging.warning('OTX URL list is empty.')

    if len(domain_list) > 0:
        for domain in domain_list:
            domain_urls = getUrlsForDomain(domain)

            if len(domain_urls) > 0:
                url_list.extend(domain_urls)

    else:
        logging.warning('OTX domain list is empty.')

    if len(ip_list) > 0:
        for ip_addr in ip_list:
            ip_results = getUrlsForIp(ip_addr)

            if len(ip_results) > 0:
                url_list.extend(ip_results)

    else:
        logging.warning('OTX IP list is empty.')

    if len(url_list) > 0:
        url_list = getSignificantItems(url_list)

    else:
        logging.warning('Cannot process empty URL list.')

    return url_list
