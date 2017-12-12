#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from MachineUtils import getSignificantItems
from StringUtils import soupParse
from VirusTotal import getUrlsForIp


import os
import re
import sys


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def queryCrimeTracker():
    try:
        ipList = []

        logging.info('Fetching latest CyberCrime Tracker list.')

        xml = soupParse('https://cybercrime-tracker.net/rss.xml')

        if xml:
            for row in xml('description'):
                ip_addr = re.findall(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', str(row.text))
                if len(ip_addr) > 0:
                    ipList.append(ip_addr[0])

        else:
            logging.error('Empty CyberCrime Tracker XML. Potential connection error. Please try again later.')

    except Exception as e:
        logging.warning('Problem connecting to CyberCrime Tracker. Aborting task.')
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)

    return ipList

def getCrimeList():
    ip_list = queryCrimeTracker()

    if len(ip_list) > 0:
        url_list = []

        for ip_addr in ip_list:
            ip_urls = getUrlsForIp(ip_addr)

            if len(ip_urls) > 0:
                url_list.extend(ip_urls)

        if len(url_list) > 0:
            url_list = getSignificantItems(url_list)
            return url_list

        else:
            logging.warning('Cannot process empty URL list.')

    else:
        logging.warning('Cannot process empty IP list.')

    return []