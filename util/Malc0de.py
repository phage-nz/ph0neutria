#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from StringUtils import isValidUrl, soupParse
import os
import re
import sys

cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)

def getMalc0deList():
    rawList = []

    logging.info("Fetching latest Malc0de list.")

    xml = soupParse(baseConfig.malc0deUrl)

    if xml:
        for row in xml('description'):
            rawList.append(row)
        del rawList[0]

        malList = []

        for row in rawList:
            location = re.sub('&amp;','&',str(row).split()[1]).replace(',','')
            if location.strip():
                url = 'http://{0}'.format(location)
                if isValidUrl(url):
                    malList.append(url)

        return malList

    else:
        logging.error("Empty Malc0de XML. Potential connection error. Please try again later.")
        sys.exit(1)
