#!/usr/bin/python
from ConfigUtils import getBaseConfig
from datetime import datetime, timedelta
from LogUtils import getModuleLogger
from MachineUtils import getSignificantItems
from VirusTotal import getUrlsForDomain


import os
import requests
import string
import sys


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)


logging = getModuleLogger(__name__)


def getDnsBh():
    try:
        logging.info('Querying DNS-BH...')

        userAgent = {'User-agent': baseConfig.userAgent}

        endpoint = 'http://mirror1.malwaredomains.com/files/{0}.txt'.format(datetime.now().strftime('%Y%m%d'))      
        request = requests.get(endpoint, headers=userAgent)

        if request.status_code == 200:
            logging.info('A blocklist from today was available.')
            return request.text

        elif request.status_code == 404:
            days_back = int(baseConfig.osintDays) + 1

            for n in range(1,days_back):
                datestamp = (datetime.now() - timedelta(days = n)).strftime('%Y%m%d')
                endpoint = 'http://mirror1.malwaredomains.com/files/{0}.txt'.format(datestamp)
                request = requests.get(endpoint, headers=userAgent)

                if request.status_code == 200:
                    logging.info('A blocklist from {0} day(s) ago was available.'.format(n))
                    return request.text

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to DNS-BH. Error: {0}'.format(e))
        
    return False


def getTexpert():
    try:
        logging.info('Querying Threatexpert...')

        userAgent = {'User-agent': baseConfig.userAgent}

        endpoint = 'http://www.networksec.org/grabbho/block.txt'     
        request = requests.get(endpoint, headers=userAgent)

        if request.status_code == 200:
            return request.text

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to Threatexpert. Error: {0}'.format(e))

    except Exception as e:
        logging.warning('Problem connecting to Threatexpert. Aborting task.')
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)

    return False


def getBadDomains():
    domain_list = []
    dnsbh_file = getDnsBh()

    if dnsbh_file:
        file_lines = dnsbh_file.splitlines()
        for line in file_lines:
            parts = line.strip().split('\t')
            if parts[1] != 'phishing':
                domain_list.append(parts[0])

    else:
        logging.error('Failed to retrieve DNS-BH file.')

    texpert_file = getTexpert()

    if texpert_file:
        file_lines = texpert_file.splitlines()
        for line in (line for line in file_lines if not line.startswith('#') and line != None):
            domain_list.append(line.strip())

    else:
        logging.error('Failed to retrieve Threatexpert file.')

    return domain_list


def getBLList():
    domain_list = getBadDomains()

    if len(domain_list) > 0:
        url_list = []

        for domain in domain_list:
            domain_urls = getUrlsForDomain(domain)

            if len(domain_urls) > 0:
                url_list.extend(domain_urls)

        if len(url_list) > 0:
            url_list = getSignificantItems(url_list)
            return url_list

        else:
            logging.warning('Cannot process empty URL list.')

    else:
        logging.warning('Cannot process empty domain list.')
    
    return []
