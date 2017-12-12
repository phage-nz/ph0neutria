#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from StringUtils import isValidUrl


import os
import requests
import sys


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def getVXList():
    try:
        userAgent = {'User-agent': baseConfig.userAgent}

        logging.info('Fetching latest VX Vault list.')

        request = requests.get('http://vxvault.net/URL_List.php', headers=userAgent)

        if request.status_code == 200:
            mal_list = []

            for line in request.content.split('\n'):
                url = line.strip()
                if isValidUrl(url):
                    mal_list.append(url)
            return mal_list
                
        else:
            logging.error('Problem connecting to VX Vault. Status code:{0}. Please try again later.'.format(request.status_code))

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to VX Vault. Error: {0}'.format(e))

    except Exception as e:
        logging.warning('Problem connecting to VX Vault. Aborting task.')
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)

    return []
