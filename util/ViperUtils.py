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


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def uploadToViper(filePath, fileName, fileUrl):
    try:
        sample_data = {'tag_list': getTags(fileUrl), 'note_title': 'Sample Source', 'note_body': getNotes(fileUrl), 'file_name': fileName}
        auth_header = {'Authorization': baseConfig.viperApiToken}

        print('Adding to Viper: {0}'.format(fileName))

        with open(filePath, 'rb') as rawFile:
            response = requests.post(baseConfig.viperUrlAdd, headers=auth_header, files={'file': rawFile}, data=sample_data)

            if response.status_code == 201:
                responsejson = json.loads(response.content)
                logging.info('Submitted file to Viper. Sample URL: {0}'.format(responsejson[0]['url']))
                return True

            elif response.status_code == 400:
                logging.info('File already exists in Viper.')

            else:
                print('Problem submitting file {0} to Viper. Status code: {1}. Continuing.'.format(fileName, response.status_code))

    except requests.exceptions.ConnectionError as e:
        print('Problem connecting to Viper. Error: {0}'.format(e))

    except Exception as e:
        print('Problem connecting to Viper. Aborting task.')
        print(sys.exc_info())
        print(type(e))
        print(e.args)
        print(e)

    return False


def getTags(fileUrl):
    tags = MutableString()

    tags += time.strftime(baseConfig.dateFormat)
    tags += ', '
    tags += urlparse(fileUrl).hostname
    tags += ', '
    tags += 'ph0neutria'

    logging.debug('tags={0}'.format(tags))

    return str(tags)

def getNotes(fileUrl):
    note = MutableString()

    note += fileUrl

    logging.debug('note={0}'.format(note))

    return str(note)
