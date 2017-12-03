#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from StringUtils import isValidUrl, randomString
from urlparse import urlparse


import json
import os
import requests
import sys


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def getMalShareList():
    try:
        payload = {'action': 'getsourcesraw', 'api_key': baseConfig.malShareApiKey }
        userAgent = {'User-agent': baseConfig.userAgent}

        logging.info('Fetching latest MalShare list.')

        request = requests.get('http://malshare.com/api.php', params=payload, headers=userAgent)

        if request.status_code == 200:
            malList = []

            for line in request.content.split('\n'):
                url = line.strip()
                if isValidUrl(url):
                    malList.append(url)
            return malList
                
        else:
            logging.error('Problem connecting to MalShare. Status code:{0}. Please try again later.'.format(request.status_code))

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to Malshare. Error: {0}'.format(e))

    except Exception as e:
        logging.warning('Problem connecting to Malshare. Aborting task.')
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)

    return []
