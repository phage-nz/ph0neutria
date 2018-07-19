#!/usr/bin/env python

import datetime
import os

import shodan
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from MachineUtils import getSignificantItems
from VirusTotal import getUrlsForIp

cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


api = shodan.Shodan(baseConfig.shodanKey)


def queryShodan():
    try:
        logging.info('Querying Shodan...')

        days_back = int(baseConfig.osintDays) + 1
        limit_date = (datetime.date.today() - datetime.timedelta(days=days_back)).strftime('%d/%m/%Y')
        search_term = 'category:malware after:{0}'.format(limit_date)

        results = api.search(search_term, page=1)

        logging.info('Shodan results found: {0}'.format(results['total']))

        pages = results['total']/100

        if results['total']%100 > 0:
            pages += 1

            ip_list = []

            for n in range(1, pages+1):
                if n > 1:
                    results = api.search(search_term, page=n)

                logging.info('Fetched page {0} of {1}...'.format(n, pages))

                for result in results['matches']:
                    ip_list.append(result['ip_str'])

            return ip_list

        else:
            return []

    except shodan.APIError as e:
        logging.info('Error: {0}'.format(e))
        return []


def getShodanList():
    url_list = []
    ip_list = queryShodan()
    
    if len(ip_list) > 0:
        for ip_addr in ip_list:
            urls = getUrlsForIp(ip_addr)
        
            if len(urls) > 0:
                url_list.extend(urls)

        if len(url_list) > 0:
            url_list = getSignificantItems(url_list)
            return url_list

        else:
            logging.warning('Failed to retrieve any URLs from VirusTotal.')

    else:
        logging.warning('Failed to retrieve any IP addresses from Shodan.')

    return []
