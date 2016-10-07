#!/usr/bin/python
from itertools import islice
from common.multiPartForm import MultiPartForm
from common.stringHelpers import md5Sum, randomString, soupParse as parse
from ConfigParser import SafeConfigParser
from UserString import MutableString
import json
import logging
import multiprocessing
import os
import re
import requests
import string
import sys
import time
import urllib
import urllib2

#       .__    _______                        __         .__       
#______ |  |__ \   _  \   ____   ____  __ ___/  |________|__|____  
#\____ \|  |  \/  /_\  \ /    \_/ __ \|  |  \   __\_  __ \  \__  \ 
#|  |_> >   Y  \  \_/   \   |  \  ___/|  |  /|  |  |  | \/  |/ __ \_
#|   __/|___|  /\_____  /___|  /\___  >____/ |__|  |__|  |__(____  /
#|__|        \/       \/     \/     \/                           \/
#
#                   ph0neutria malware crawler
#                             v0.1
#              https://github.com/t0x0-nz/ph0neutria

pwd = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(pwd, 'res', 'banner.txt'), 'r') as banner:
        print banner.read()

logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.INFO)

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
API_KEY = parser.get("MalShare", "apikey")
MALC0DE_URL = parser.get("Malc0de", "url")
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
        webs.append(malc0deWeb)
        webs.append(malshareWeb)
        malc0deWeb.start()
        malshareWeb.start()

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

def startMalc0de():
    for mUrl in getMalc0deList():
        if not isInViper(url=mUrl):
            logging.info("Downloading from the wild: {0}".format(mUrl))
            getWildFile(mUrl)

def startMalShare():
    for mHash in getMalShareList():
        if not isInViper(fileHash=mHash):
            logging.info("Downloading from MalShare: {0}".format(mHash))
            getMalShareFile(mHash)

def getMalShareList():
    try:
        userAgent = {'User-agent': USER_AGENT}

        request = requests.get(MALSHARE_DIGEST, headers=userAgent)

        if request.status_code == 200:
            for line in request.content.split('\n'):
                logging.debug("Yield line: {0}".format(line))
                yield line
            logging.debug("No more lines.")
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

    xml = parse(MALC0DE_URL)

    if xml:
        for row in xml('description'):
            rawList.append(row)
        del rawList[0]

        malList = []

        for row in rawList:
            location = re.sub('&amp;','&',str(row).split()[1]).replace(',','')
            url = 'http://{0}'.format(location)
            malList.append(url)

        return malList

    else:
        logging.error("Empty Malc0de XML. Please try again later.")
        sys.exit(1)

def getMalShareFile(fileHash):
    try:
        payload = {'action': 'getfile', 'api_key': API_KEY, 'hash' : fileHash }
        userAgent = {'User-agent': USER_AGENT}

        request = requests.get(MALSHARE_API, params=payload, headers=userAgent)

        if request.status_code == 200:
            response = request.content

            if response == "Sample not found":
                logging.error("Sample not found.")
                return None
            if response == "ERROR! => Account not activated":
                logging.error("Bad API key.")
                sys.exit(1)
            if response == "ERROR! => Over Request Limit.":
                logging.error("Exceeded MalShare request quota.")
                sys.exit(1)

            filePath = os.path.join(OUTPUT_FOLDER, fileHash)
            open(filePath,"wb").write(response)
            logging.info("Saved as file: {0}".format(filePath))

            tags = getTags(fileHash, "malshare-spider")
            uploadToViper(filePath, fileHash, tags)

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

def getWildFile(url):
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
            fileMd5 = md5Sum(tmpFilePath)
            filePath = os.path.join(OUTPUT_FOLDER, fileMd5)
            os.rename(tmpFilePath, filePath)
            logging.info("Renamed as file: {0}. Checking Viper again.".format(filePath))

            if not isInViper(fileHash=fileMd5):
                tags = getTags(fileMd5, "wild-spider", source=url)
                uploadToViper(filePath, fileMd5, tags)

            if DELETE_OUTPUT.lower() == "yes":
                logging.info("Removing file: {0}".format(filePath))
                os.remove(filePath)
 
        else:
            logging.error("Problem connecting to {0}. Status code: {1}. Continuing.".format(url, request.status_code))

    except Exception as e:
        logging.error("Problem connecting to {0}. Continuing.".format(url))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        #sys.exit(1)

def uploadToViper(filePath, fileName, tags):
    rawFile = open(filePath, 'rb')
    logging.debug(VIPER_URL_ADD + " file=" + fileName)

    try:
        form = MultiPartForm()
        form.add_file('file', fileName, fileHandle=rawFile)
        form.add_field('tags', tags)

        logging.info("Adding to Viper: {0}".format(fileName))

        request = urllib2.Request(VIPER_URL_ADD)

        body = str(form)
        request.add_header('Content-type', form.get_content_type())
        request.add_header('Content-length', len(body))
        request.add_data(body)

        responseData = urllib2.urlopen(request, timeout=60).read()
        reponsejson = json.loads(responseData)
        logging.info("Submitted to Viper, message: {0}".format(reponsejson["message"]))
    except urllib2.URLError as e:
        logging.info("Non 200 HTTP code: {0}".format(e.code))
        raise Exception("Unable to establish connection to Viper REST API server: {0}".format(e))
    except urllib2.HTTPError as e:
        logging.info("Non 200 HTTP code: {0}".format(e.code))
        raise Exception("Unable to perform HTTP request to Viper REST API server: {0}".format(e))
    except ValueError as e:
        raise Exception("Unable to convert response to JSON: {0}".format(e))

    if reponsejson["message"] != 'added':
        raise Exception("Failed to store file in Viper: {0}".format(reponsejson["message"]))

def getTags(fileHash, agent, source=None):
    tags = MutableString()

    if source is None:
        try:
            payload = {'action': 'details', 'api_key': API_KEY, 'hash' : fileHash }
            userAgent = {'User-agent': USER_AGENT}

            request = requests.get(MALSHARE_API, params=payload, headers=userAgent)

            if request.status_code == 200:
                sources = json.loads(request.content)
                source = sources['SOURCES'][0]
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

    if source:
      tags += source
      tags += ","
    tags += fileHash
    tags += ","
    tags += agent

    logging.info("tags={0}".format(tags))

    return str(tags)

def isInViper(fileHash=None,url=None):

    if not fileHash == None:
        param = { 'md5': fileHash }

    if not url == None:
        param = { 'tag': url }

    param['project'] = 'default'

    requestData = urllib.urlencode(param)

    try:
        request = urllib2.Request(VIPER_URL_FIND, requestData)
        response = urllib2.urlopen(request, timeout=60)
        responseData = response.read()

    except urllib2.HTTPError as e:
        if e.code == 400:
            logging.info("400 Invalid Search Term: ({0})".format(str(param)))
            return False
        else:
            raise Exception("Unable to perform HTTP request to Viper (HTTP code={0})".format(e))
    except urllib2.URLError as e:
        raise Exception("Unable to establish connection to Viper: {0}".format(e))

    try:
        check = json.loads(responseData)
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
                        logging.info("File {0} is in Viper".format(fileHash))
                        return True
                if not url == None:
                    if url in v['tags']:
                        logging.info("File from {0} is in Viper".format(url))
                        return True
    if not fileHash == None:
        logging.info("File {0} is not in Viper".format(fileHash))
    if not url == None:
        logging.info("File from {0} is not in Viper".format(url))
    return False

if __name__ == "__main__":
    main()
