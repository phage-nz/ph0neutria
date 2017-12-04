#!/usr/bin/python

from ConfigUtils import getBaseConfig
from datetime import datetime
from LogUtils import getModuleLogger
from MachineUtils import getSignificantItems
from VirusTotal import getUrlsForIp


import json
import os
import requests
import sys
import time


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)


logging = getModuleLogger(__name__)


def queryPayload():
    try:
        keyword_list = ['beacon','c2 commands','checkin','configuration request','downloader','file download','gate.php','exe download','executable download','dl exe','exe dl']

        userAgent = {'User-agent': baseConfig.userAgent} 

        logging.info('Fetching recent interesting items from Payload Security...')

        request = requests.get('https://www.hybrid-analysis.com/feed?json', headers=userAgent)

        if request.status_code == 200:
            report = json.loads(request.text)
            items = report['data']

            ip_list = []

            for item in items:
                if 'threatscore' in item and 'domains' in item and 'et_alerts' in item:
                    investigate = False
                    if item['threatscore'] > 80:
                        for alert in item['et_alerts']:
                            if any(s in alert['action']['description'].lower() for s in keyword_list if s != None):
                                if 'srcip' in alert:
                                    src_ip = alert['srcip']
                                    if not src_ip in ip_list:
                                        ip_list.append(src_ip)

            return ip_list

        else:
            logging.critical('Failed to retrieve Payload Security feed.')

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to Payload Security. Error: {0}'.format(e))

    except Exception as e:
        logging.warning('Problem connecting to Payload Security. Aborting task.')
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)

    return []


def getPLList():
    url_list = []
    ip_list = queryPayload()
    
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
        logging.warning('Failed to retrieve any IP addresses from alerts.')

    return []