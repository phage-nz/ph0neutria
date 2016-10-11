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

        logging.info("Fetching latest VX Vault list.")

        request = requests.get(baseConfig.vxVaultUrl, headers=userAgent)

        if request.status_code == 200:
            malList = []

            for line in request.content.split('\n'):
                url = line.strip()
                if isValidUrl(url):
                    malList.append(url)
            return malList
                
        else:
            logging.error("Problem connecting to VX Vault. Status code:{0}. Please try again later.".format(request.status_code))
            sys.exit(1)

    except Exception as e:
        logging.error("Problem connecting to VX Vault. Please try again later.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        sys.exit(1)
