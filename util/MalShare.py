#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from StringUtils import md5SumFile, randomString
from urlparse import urlparse
from ViperUtils import getTags, uploadToViper, isNewEntry
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
        userAgent = {'User-agent': baseConfig.userAgent}

        logging.info("Fetching latest MalShare list.")

        request = requests.get(baseConfig.malShareDigest, headers=userAgent)

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

def getMalShareSource(fileHash):
    try:
        payload = {'action': 'details', 'api_key': baseConfig.malShareApiKey, 'hash' : fileHash }
        userAgent = {'User-agent': baseConfig.userAgent}

        request = requests.get(baseConfig.malShareApi, params=payload, headers=userAgent)

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

def getMalShareFile(fileHash):
    try:
        payload = {'action': 'getfile', 'api_key': baseConfig.malShareApiKey, 'hash' : fileHash }
        userAgent = {'User-agent': baseConfig.userAgent}

        request = requests.get(baseConfig.malShareApi, params=payload, headers=userAgent)

        if request.status_code == 200:
            response = request.content

            if "Sample not found" in response:
                logging.warning("Sample not found.")
                return False
            if "Account not activated" in response:
                logging.error("Bad API key.")
                sys.exit(1)
            if "Over Request Limit" in response:
                logging.error("Exceeded MalShare request quota. Please temporarily disable MalShare.")
                sys.exit(1)

            tmpName = randomString(32)
            tmpFilePath = os.path.join(baseConfig.outputFolder, tmpName)
            open(tmpFilePath,"wb").write(response)
            logging.info("Saved as temporary file: {0}. Calculating MD5.".format(tmpFilePath))

            fileMD5 = md5SumFile(tmpFilePath)
            filePath = os.path.join(baseConfig.outputFolder, fileMD5)
            os.rename(tmpFilePath, filePath)
            logging.info("Renamed as file: {0}. Checking Viper again.".format(filePath))

            if isNewEntry(fileHash=fileMD5):
                url = getMalShareSource(fileHash)
                fileName = url.split('/')[-1]
                tags = getTags(fileMD5, url, "malshare-spider")
                uploadToViper(filePath, fileName, tags)

                if baseConfig.deleteOutput.lower() == "yes":
                    logging.info("Removing file: {0}".format(filePath))
                    os.remove(filePath)

                return True

            else:
                logging.info("Removing file: {0}".format(filePath))
                os.remove(filePath)
                return False

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
