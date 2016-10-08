#!/usr/bin/python
from itertools import islice
from common.stringHelpers import *
from ConfigParser import SafeConfigParser
from urlparse import urlparse
from UserString import MutableString
from requests_toolbelt.multipart.encoder import MultipartEncoder
import coloredlogs
import json
import logging
import multiprocessing
import os
import re
import requests
import string
import sys
import time

#       .__    _______                        __         .__       
#______ |  |__ \   _  \   ____   ____  __ ___/  |________|__|____  
#\____ \|  |  \/  /_\  \ /    \_/ __ \|  |  \   __\_  __ \  \__  \ 
#|  |_> >   Y  \  \_/   \   |  \  ___/|  |  /|  |  |  | \/  |/ __ \_
#|   __/|___|  /\_____  /___|  /\___  >____/ |__|  |__|  |__(____  /
#|__|        \/       \/     \/     \/                           \/
#
#                   ph0neutria malware crawler
#                             v0.3
#              https://github.com/t0x0-nz/ph0neutria

pwd = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(pwd, 'res', 'banner.txt'), 'r') as banner:
        print banner.read()

logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.INFO)
coloredlogs.install()

logging.info("Loading configuration...")
parser = SafeConfigParser()
parser.read(os.path.join(pwd, 'config', 'settings.conf'))

MULTI_PROCESS = parser.get("Core", "multiprocess")
USER_AGENT = parser.get("Core", "useragent")
OUTPUT_FOLDER_NAME = parser.get("Core", "outputfolder")
OUTPUT_FOLDER = os.path.join(pwd, OUTPUT_FOLDER_NAME)
DELETE_OUTPUT = parser.get("Core", "deleteoutput")
MALSHARE_API = parser.get("MalShare", "apiurl")
MALSHARE_DIGEST = parser.get("MalShare", "dailyurl")
MS_API_KEY = parser.get("MalShare", "apikey")
MALC0DE_URL = parser.get("Malc0de", "url")
VXVAULT_URL = parser.get("VXVault", "url")
VIPER_URL_ADD = parser.get("Viper", "addurl")
VIPER_URL_FIND = parser.get("Viper", "findurl")

def main(): 
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    if MULTI_PROCESS.lower() == "yes":
        logging.info("Spawning multiple ph0neutria processes. Press CTRL+C to terminate.")
        webs = []
        malc0deWeb = multiprocessing.Process(target=startMalc0de)
        malshareWeb = multiprocessing.Process(target=startMalShare)
        vxVaultWeb = multiprocessing.Process(target=startVXVault)
        webs.append(malc0deWeb)
        webs.append(malshareWeb)
        webs.append(vxVaultWeb)
        malc0deWeb.start()
        malshareWeb.start()
        vxVaultWeb.start()

        try:
            for web in webs:
                web.join()
        except KeyboardInterrupt:
            logging.info("Mother spider received Ctrl+C. Killing babies.")
            for web in webs:
                web.terminate()
                web.join()
                
    else:
        logging.info("Spawning single ph0neutria process. Press CTRL+C to terminate.")
        startMalc0de()
        startMalShare()
        startVXVault()

def startMalc0de():
    for mUrl in getMalc0deList():
        mUrlHash = md5SumString(mUrl)
        if not isInViper(urlHash=mUrlHash):
            logging.info("Downloading from the wild: {0}".format(mUrl))
            getWildFile(mUrl, mUrlHash)

def startMalShare():
    for mHash in getMalShareList():
        if not isInViper(fileHash=mHash):
            logging.info("Downloading from MalShare: {0}".format(mHash))
            getMalShareFile(mHash)

def startVXVault():
    for vUrl in getVXList():
        print vUrl
        vUrlHash = md5SumString(vUrl)
        if not isInViper(urlHash=vUrlHash):
            logging.info("Downloading from the wild: {0}".format(vUrl))
            getWildFile(vUrl, vUrlHash)

def getMalShareList():
    try:
        userAgent = {'User-agent': USER_AGENT}

        logging.info("Fetching latest MalShare list.")

        request = requests.get(MALSHARE_DIGEST, headers=userAgent)

        if request.status_code == 200:
            malList = []

            for line in request.content.split('\n'):
                malList.append(line.strip())
            return malList

        else:
            logging.error("Problem connecting to MalShare. Status code:{0}. Please try again later.".format(request.status_code))
            sys.exit(1)

    except Exception as e:
        logging.error("Problem connecting to MalShare. Please try again later.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        sys.exit(1)

def getMalc0deList():
    rawList = []

    logging.info("Fetching latest Malc0de list.")

    xml = soupParse(MALC0DE_URL)

    if xml:
        for row in xml('description'):
            rawList.append(row)
        del rawList[0]

        malList = []

        for row in rawList:
            location = re.sub('&amp;','&',str(row).split()[1]).replace(',','')
            if location.strip():
                url = 'http://{0}'.format(location)
                malList.append(url)

        return malList

    else:
        logging.error("Empty Malc0de XML. Potential connection error. Please try again later.")
        sys.exit(1)

def getVXList():
    try:
        userAgent = {'User-agent': USER_AGENT}

        logging.info("Fetching latest VX Vault list.")

        request = requests.get(VXVAULT_URL, headers=userAgent)

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

def getMalShareFile(fileHash):
    try:
        payload = {'action': 'getfile', 'api_key': MS_API_KEY, 'hash' : fileHash }
        userAgent = {'User-agent': USER_AGENT}

        request = requests.get(MALSHARE_API, params=payload, headers=userAgent)

        if request.status_code == 200:
            response = request.content

            if response == "Sample not found":
                logging.warning("Sample not found.")
                return None
            if response == "ERROR! => Account not activated":
                logging.error("Bad API key.")
                sys.exit(1)
            if response == "ERROR! => Over Request Limit.":
                logging.error("Exceeded MalShare request quota.")
                sys.exit(1)

            tmpName = randomString(32)
            tmpFilePath = os.path.join(OUTPUT_FOLDER, tmpName)
            open(tmpFilePath,"wb").write(response)
            logging.info("Saved as temporary file: {0}. Calculating MD5.".format(tmpFilePath))

            # For whatever reason cannot even trust MalShare MD5 sums.
            fileMD5 = md5SumFile(tmpFilePath)
            filePath = os.path.join(OUTPUT_FOLDER, fileMD5)
            os.rename(tmpFilePath, filePath)
            logging.info("Renamed as file: {0}. Checking Viper again.".format(filePath))

            if not isInViper(fileHash=fileMD5):
                url = getMalShareSource(fileHash)
                fileName = url.split('/')[-1]
                tags = getTags(fileMD5, url, "malshare-spider")
                uploadToViper(filePath, fileName, tags)

            if DELETE_OUTPUT.lower() == "yes":
                logging.info("Removing file: {0}".format(filePath))
                os.remove(filePath)

        else:
            logging.error("Problem connecting to MalShare. Status code: {0}. Please try again later.".format(request.status_code))
            sys.exit(1)
    
    except Exception as e:
        logging.error("Problem connecting to MalShare. Please try again later.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        sys.exit(1)

def getWildFile(url, urlMD5):
    try:
        userAgent = {'User-agent': USER_AGENT}

        request = requests.get(url, headers=userAgent)

        if request.status_code == 200:
            response = request.content

            tmpName = randomString(32)
            tmpFilePath = os.path.join(OUTPUT_FOLDER, tmpName)
            open(tmpFilePath,"wb").write(response)
            logging.info("Saved as temporary file: {0}. Calculating MD5.".format(tmpFilePath))

            # Do not trust wild MD5 sums.
            fileMD5 = md5SumFile(tmpFilePath)
            filePath = os.path.join(OUTPUT_FOLDER, fileMD5)
            os.rename(tmpFilePath, filePath)
            logging.info("Renamed as file: {0}. Checking Viper again.".format(filePath))

            if not isInViper(fileHash=fileMD5):
                fileName = url.split('/')[-1]
                tags = getTags(fileMD5, url, "wild-spider", urlHash=urlMD5)
                uploadToViper(filePath, fileName, tags)

            if DELETE_OUTPUT.lower() == "yes":
                logging.info("Removing file: {0}".format(filePath))
                os.remove(filePath)
 
        else:
            logging.warning("Problem connecting to {0}. Status code: {1}. Continuing.".format(url, request.status_code))

    except requests.exceptions.ConnectionError as e:
        logging.warning("Problem connecting to {0}. Error: {1}".format(url, e))

    except Exception as e:
        logging.warning("Problem connecting to {0}. Continuing.".format(url))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        #sys.exit(1)

def uploadToViper(filePath, fileName, tags):
    rawFile = open(filePath, 'rb')

    try:
        files = {'file': (fileName, rawFile)}
        tags = {'tags': tags}
        headers = {'User-agent': USER_AGENT}
 
        logging.info("Adding to Viper: {0}".format(fileName))

        response = requests.post(VIPER_URL_ADD, headers=headers, files=files, data=tags)

        if response.status_code == 200:
            responsejson = json.loads(response.content)
            logging.info("Submitted to Viper, message: {0}".format(responsejson["message"]))

        else:
            logging.warning("Problem submitting {0} to Viper. Status code: {1}. Continuing.".format(fileName, response.status_code))

    except Exception as e:
        logging.warning("Problem submitting {0} to Viper. Continuing.".format(fileName))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        #sys.exit(1)

def getMalShareSource(fileHash):
    try:
        payload = {'action': 'details', 'api_key': MS_API_KEY, 'hash' : fileHash }
        userAgent = {'User-agent': USER_AGENT}

        request = requests.get(MALSHARE_API, params=payload, headers=userAgent)

        if request.status_code == 200:
            sources = json.loads(request.content)
            source = sources['SOURCES'][0]
            return source
        else:
            logging.error("Problem connecting to MalShare. Status code: {0}. Please try again later.".format(request.status_code))
            sys.exit(1)

    except Exception as e:
        logging.error("Problem connecting to MalShare. Please try again later.")
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        sys.exit(1)

def getTags(fileHash, url, agent, urlHash=None):
    tags = MutableString()

    tags += fileHash
    tags += ","
    tags += urlparse(url).hostname
    tags += ","
    tags += url
    tags += ","

    if not urlHash == None:
        tags += urlHash
        tags += ","

    tags += agent

    logging.debug("tags={0}".format(tags))

    return str(tags)

def isInViper(fileHash=None,urlHash=None):

    if not fileHash == None:
        params = { 'md5': fileHash.lower(), 'project': 'default' }

    if not urlHash == None:
        # Viper tags are all lowercase - for now.
        params = { 'tag': urlHash.lower(), 'project': 'default' }

    try:
        userAgent = {'User-agent': USER_AGENT}

        response = requests.post(VIPER_URL_FIND, data=params, headers=userAgent)

        if not response.status_code == 200:
            if response.status_code == 400:
                logging.warning("400 Invalid Search Term: ({0})".format(str(param)))
                return False
            else:
                logging.warning("Unable to perform HTTP request to Viper (HTTP code={0})".format(response.status_code))
    except Exception as e:
        raise Exception("Unable to establish connection to Viper: {0}".format(e))

    try:
        check = json.loads(response.content)
        check = check['results']

    except ValueError as e:
        raise Exception("Unable to convert response to JSON: {0}".format(e))

    for i in check:
        if str(i) == "../":
            return False
        if str(i) == "default":
            for v in check[i]:
                if not fileHash == None:
                    if v['md5'] == fileHash:
                        logging.info("File with hash: {0} is in Viper".format(fileHash))
                        return True
                if not urlHash == None:
                    if urlHash in v['tags']:
                        logging.info("URL with hash: {0} is in Viper".format(urlHash))
                        return True
    if not fileHash == None:
        logging.info("File with hash {0} is not in Viper".format(fileHash))
    if not urlHash == None:
        logging.info("URL with hash {0} is not in Viper".format(urlHash))
    return False

if __name__ == "__main__":
    main()
