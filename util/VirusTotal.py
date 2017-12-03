from ConfigUtils import getBaseConfig
from datetime import datetime, timedelta
from LogUtils import getModuleLogger
from StringUtils import cleanUrl, containsNoStopwords
from urlparse import urlparse


import json
import os
import requests
import sys
import time


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)


logging = getModuleLogger(__name__)


def getUrlsForIp(ip_addr):
    params = {'apikey': baseConfig.vtKey, 'ip': ip_addr}
    headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent': baseConfig.vtUser}

    logging.info('Querying VirusTotal for URLs associated with: {0}'.format(ip_addr))
    response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params, headers=headers)

    logging.info('Waiting for a moment...')
    time.sleep(7)

    if response.status_code == 200:
        vtReport = json.loads(response.text)
        if vtReport['response_code'] == 0:
            logging.info('Address not found.')

        if vtReport['response_code'] == 1:
            if 'detected_urls' in vtReport:
                urls = []
                for url in vtReport['detected_urls']:
                    days_back = int(baseConfig.osintDays) + 1
                    scan_date = datetime.strptime(url['scan_date'], '%Y-%m-%d %H:%M:%S')

                    if scan_date > (datetime.now() - timedelta(days=days_back)):
                        url_loc = url['url']
                        if urlparse(url_loc).path != '/':
                            url_loc = url_loc.replace('`','')
                            if containsNoStopwords(url_loc):
                                urls.append(cleanUrl(url_loc))
                return urls
            else:
                logging.info('None found.')

        return []

    else:
        logging.critical('Failed to query VirusTotal.')
        logging.warning(response.text)
        sys.exit(1)


def getUrlsForDomain(domain):
    params = {'apikey': baseConfig.vtKey, 'domain': domain}
    headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent': baseConfig.vtUser}

    logging.info('Querying VirusTotal for Passive DNS records associated with: {0}'.format(domain))
    response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params, headers=headers)

    logging.info('Waiting for a moment...')
    time.sleep(7)

    if response.status_code == 200:
        vtReport = json.loads(response.text)
        if vtReport['response_code'] == 0:
            logging.info('Domain not found.')

        if vtReport['response_code'] == 1:
            if 'resolutions' in vtReport:
                resolutions = vtReport['resolutions']

                if len(resolutions) > 0:
                    ip_list = []
                    # Add most recent IP.
                    ip_list.append(resolutions[0]['ip_address'])

                    for ip_addr in resolutions:
                        days_back = int(baseConfig.osintDays) + 1

                        if ip_addr['last_resolved'] != None:
                            last_resolved = datetime.strptime(ip_addr['last_resolved'], '%Y-%m-%d %H:%M:%S')

                            if last_resolved > (datetime.now() - timedelta(days=days_back)):
                                if not ip_addr['ip_address'] in ip_list:
                                    ip_list.append(ip_addr['ip_address'])

                    if len(ip_list) > 0:
                        url_list = []

                        for ip_addr in ip_list:
                            urls = getUrlsForIp(ip_addr)
                        
                            if len(urls) > 0:
                                url_list.extend(urls)

                        return url_list

                    else:
                        logging.info('No recent resolutions found for domain: {0}'.format(domain))

                else:
                    logging.info('Empty resolution list found for domain: {0}'.format(domain))

            else:
                logging.info('No resolutions found for domain: {0}'.format(domain))

        return []

    else:
        logging.critical('Failed to query VirusTotal.')
        logging.warning(response.text)
        sys.exit(1)
