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

def getMinotaurList():
    logging.info("Fetching latest Minotaur list.")

    html = soupParse(baseConfig.minotaurUrl)    

    if html:
        malList = []

        urlTable = html.find("div", {"id": "mtabs-2"}).find("table", {"class": "hometable2"})
        if urlTable:
            for row in urlTable.findAll("tr")[1:]:
                elements = row.findAll('td')
                if len(elements) == 4:
                    url = elements[3].text.strip()
                    if isValidUrl(url):
                        malList.append(url)

            return malList
        else:
            logging.error("Failed to locate Minotaur URL table. Ensure that this is the latest ph0neutria release.")
            sys.exit(1)

    else:
        logging.error("Empty Minotaur XML. Potential connection error. Please try again later.")
        sys.exit(1)
