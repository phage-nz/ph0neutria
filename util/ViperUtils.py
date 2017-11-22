#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from requests_toolbelt.multipart.encoder import MultipartEncoder
from urlparse import urlparse
from UserString import MutableString
import json
import os
import requests
import sys
import time
import hashlib

cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)

def sha256(fname):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def uploadToViper(filePath, fileName, informations):
    rawFile = open(filePath, 'rb')

    try:
        files = {'file': (fileName, rawFile)}
        
        headers = {'User-agent': baseConfig.userAgent}
        logging.info("Adding to Viper: {0}".format(fileName))
        
        data = {'sha256': sha256(filePath), 'title': 'ph0neutria', 'body': informations}
        if baseConfig.viperAddTags == 'yes':
            tags = {'tags': informations}
        else:
            tags = ""
        response = requests.post("%s/file/add"%baseConfig.viperUrl, headers=headers, files=files, data=tags)
        if response.status_code == 200:
            responsejson = json.loads(response.content)
            logging.info("Submitted to Viper, message: {0}".format(responsejson["message"]))
        else:
            logging.warning("Problem submitting {0} to Viper. Status code: {1}. Continuing.".format(fileName, response.status_code))
            return False

        if baseConfig.viperAddNotes.lower() == "yes":
            logging.info("Adding notes to Viper: {0}".format(fileName))
            data = {'sha256': sha256(filePath), 'title': 'ph0neutria', 'body': informations}
            response = requests.post("%s/file/notes/add"%baseConfig.viperUrl, headers=headers, data=data)            
            if response.status_code == 200:
                responsejson = json.loads(response.content)
                logging.info("Submitted notes to Viper, message: {0}".format(responsejson["message"]))
            else:
                logging.warning("Problem creating notes {0} to Viper. Status code: {1}. Continuing.".format(fileName, response.status_code))
                return False
        return True

    except Exception as e:
        logging.warning("Problem submitting {0} to Viper. Continuing.".format(fileName))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        return False
        #sys.exit(1)

def getInformations(url, agent, urlHash=None):
    informations = MutableString()
    informations += urlparse(url).hostname
    informations += ","
    informations += url
    informations += ","

    if not urlHash == None:
        informations += urlHash
        informations += ","

    informations += time.strftime(baseConfig.dateFormat)
    informations += ","
    informations += agent

    logging.debug("informations={0}".format(informations))

    return str(informations)

def isNewEntry(fileHash=None,urlHash=None):

    if not fileHash == None:
        params = { 'md5': fileHash.lower(), 'project': 'default' }

    if not urlHash == None:
        # Viper tags are all lowercase - for now.
        params = { 'tag': urlHash.lower(), 'project': 'default' }

    try:
        userAgent = {'User-agent': baseConfig.userAgent}

        response = requests.post("%s/file/find"%baseConfig.viperUrl, data=params, headers=userAgent)

        if not response.status_code == 200:
            if response.status_code == 400:
                logging.warning("400 Invalid Search Term: ({0})".format(str(param)))
                return False
            else:
                logging.warning("Unable to perform HTTP request to Viper (HTTP code={0})".format(response.status_code))
                return False
    except Exception as e:
        raise Exception("Unable to establish connection to Viper: {0}".format(e))
        return False

    try:
        check = json.loads(response.content)

        if check['results']:
            check = check['results']
        else:
            logging.warning("Results key not present in JSON response.")
            return False

    except ValueError as e:
        raise Exception("Unable to convert response to JSON: {0}".format(e))
        return False

    for i in check:
        if str(i) == "../":
            return False
        if str(i) == "default":
            for v in check[i]:
                if not fileHash == None:
                    if v['md5'] == fileHash:
                        logging.info("File with hash: {0} is in Viper".format(fileHash))
                        return False
                if not urlHash == None:
                    if urlHash in v['tags']:
                        logging.info("URL with hash: {0} is in Viper".format(urlHash))
                        return False
    if not fileHash == None:
        logging.info("File with hash {0} is not in Viper".format(fileHash))
        return True
    if not urlHash == None:
        logging.info("URL with hash {0} is not in Viper".format(urlHash))
        return True
    return False

