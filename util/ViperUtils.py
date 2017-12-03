#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from requests_toolbelt.multipart.encoder import MultipartEncoder
from StringUtils import md5SumString, sha256SumFile
from urlparse import urlparse
from UserString import MutableString


import json
import os
import requests
import sys
import time


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def uploadToViper(filePath, fileName, fileUrl):
    rawFile = open(filePath, 'rb')

    try:
        files = {'file': (fileName, rawFile)}

        if baseConfig.viperAddTags == 'yes':
            tags = getTags(fileUrl)
        else:
            tags =''

        tags = {'tags': tags}
        headers = {'User-agent': baseConfig.userAgent}
 
        logging.info('Adding to Viper: {0}'.format(fileName))

        response = requests.post(baseConfig.viperUrlAdd, headers=headers, files=files, data=tags)

        if response.status_code == 200:
            responsejson = json.loads(response.content)
            logging.info('Submitted file to Viper, message: {0}'.format(responsejson['message']))

            if baseConfig.viperAddNotes == 'yes':
                noteData = {'sha256': sha256SumFile(filePath), 'title': 'ph0neutria', 'body': getNotes(fileUrl)}

                response = requests.post(baseConfig.viperUrlNotes, headers=headers, data=noteData)

                if response.status_code == 200:
                    responsejson = json.loads(response.content)
                    logging.info('Submitted note to Viper, message: {0}'.format(responsejson['message']))

                else:
                    logging.warning('Problem submitting note {0} to Viper. Status code: {1}. Continuing.'.format(fileName, response.status_code))
                    return False

            return True

        else:
            logging.warning('Problem submitting file {0} to Viper. Status code: {1}. Continuing.'.format(fileName, response.status_code))

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to Viper. Error: {0}'.format(e))

    except Exception as e:
        logging.warning('Problem connecting to Viper. Aborting task.')
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)

    return False



def getTags(fileUrl):
    tags = MutableString()

    tags += time.strftime(baseConfig.dateFormat)
    tags += ','
    tags += urlparse(fileUrl).hostname
    tags += ','
    tags += 'ph0neutria'

    logging.debug('tags={0}'.format(tags))

    return str(tags)

def getNotes(fileUrl):
    note = MutableString()

    note += fileUrl

    logging.debug('note={0}'.format(note))

    return str(note)
