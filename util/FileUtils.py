#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from StringUtils import sha256SumFile, randomString
from ViperUtils import uploadToViper


import codecs
import magic
import os
import requests
import sys
import time
import urlparse


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


# TOR proxy
if baseConfig.useTor.lower() == 'yes':
    proxies = {
        'http': 'socks5://%s:%d'%(baseConfig.torIP, int(baseConfig.torPort)),
        'https': 'socks5://%s:%d'%(baseConfig.torIP, int(baseConfig.torPort))
    }
else:
    proxies = {
        'http': '',
        'https': ''
    }


def getWildFile(listedUrl):
    fileUrl, preStageOk, abortGet = headRequest(listedUrl)

    if preStageOk == True and abortGet == False and fileUrl != listedUrl:
        attempts = 2

        while attempts <= int(baseConfig.redirectLimit) and preStageOk == False and abortGet == False:
            fileUrl, preStageOk = headRequest(fileUrl)
            attempts += 1

        if preStageOk:
            fileRequest = requestUrl(fileUrl)
            addToUrlCache(fileUrl)
            return fileRequest

        else:
            logging.warning('Encountered an error in pre-stage for URL: {0}'.format(fileUrl))
            addToUrlCache(fileUrl)
            return False

    elif preStageOk: 
        fileRequest = requestUrl(fileUrl)
        addToUrlCache(fileUrl)
        return fileRequest

    else:
        addToUrlCache(fileUrl)
        return False


def headRequest(fileUrl):
    logging.info('Making HEAD request to: {0}'.format(fileUrl))

    try:
        userAgent = {'User-agent': baseConfig.userAgent}

        head = requests.head(fileUrl, headers=userAgent, proxies=proxies, timeout=(20,20))

        if head.status_code == 200:
            if 'Content-Length' in head.headers:
                fileSize = int(head.headers['Content-Length']) >> 20

                if (fileSize > 10):
                    logging.error('File is {0}MB. Too large to process.'.format(fileSize))
                    return fileUrl, False, True
                else:
                    return fileUrl, True, False
            else:
                logging.info('HEAD request to {0} did not return a Content-Length header. Attempting GET.'.format(fileUrl))
                return fileUrl, True, False

        elif head.status_code == 301 or head.status_code == 302:
            if 'Location' in head.headers:
                fileUrl = head.headers['Location']
                return fileUrl, True, False
            else:
                logging.info('HEAD request to {0} responded with a redirect without a location. Aborting task.'.format(fileUrl))
                return fileUrl, False, True

        elif head.status_code == 403:
            logging.info('HEAD request to {0} returned 403 (may not be permitted). Attempting GET.'.format(fileUrl))
            return fileUrl, True, False

        else:
            logging.warning('Problem connecting to {0}. Status code: {1}. Aborting task.'.format(fileUrl, head.status_code))
            return fileUrl, False, True

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to {0}. Error: {1}'.format(fileUrl, e))
        return fileUrl, False, True

    except Exception as e:
        logging.warning('Problem connecting to {0}. Aborting task.'.format(fileUrl))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        return fileUrl, False, True


def requestUrl(fileUrl):
    try:
        userAgent = {'User-agent': baseConfig.userAgent}

        request = requests.get(fileUrl, headers=userAgent, proxies=proxies, timeout=(20,20))

        if request.status_code == 200:
            response = request.content

            tmpName = randomString(32)
            tmpFilePath = os.path.join(baseConfig.outputFolder, tmpName)
            fileName = urlparse.urlparse(fileUrl).path.strip('/')

            open(tmpFilePath,'wb').write(response)

            processed = processDownload(tmpFilePath, fileName, fileUrl)

            return processed

        else:
            logging.warning('Problem connecting to {0}. Status code: {1}. Aborting task.'.format(fileUrl, request.status_code))
            return False

    except requests.exceptions.ConnectionError as e:
        logging.warning('Problem connecting to {0}. Error: {1}'.format(fileUrl, e))
        return False

    except Exception as e:
        logging.warning('Problem connecting to {0}. Aborting task.'.format(fileUrl))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        return False


def processDownload(tmpFilePath, fileName, fileUrl):
    logging.info('Downloaded as temporary file: {0}. Beginning processing...'.format(tmpFilePath))

    fileSize = os.path.getsize(tmpFilePath) >> 20

    if (fileSize > 10):
        logging.error('File is {0}MB. Too large to process.'.format(fileSize))
        cleanUp(tmpFilePath)
        return False

    fileHash = sha256SumFile(tmpFilePath)

    if not isAcceptedHash(fileHash):
        cleanUp(tmpFilePath)
        return False

    filePath = os.path.join(baseConfig.outputFolder, fileHash)
    os.rename(tmpFilePath, filePath)

    # Trust only the content type of the downloaded file.
    mimeType = magic.from_file(filePath, mime=True)

    if mimeType not in ['application/octet-stream', 'application/x-dosexec', 'application/x-msdownload', 'application/x-ms-installer', 'application/pdf', 'application/x-pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template', 'application/vnd.ms-word.document.macroEnabled', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.openxmlformats-officedocument.spreadsheetml.template', 'application/vnd.ms-excel.sheet.macroEnabled', 'application/vnd.ms-excel.template.macroEnabled', 'application/vnd.ms-excel.addin.macroEnabled', 'application/vnd.ms-excel.sheet.binary.macroEnabled', 'application/x-shockwave-flash']:
        logging.error('Detected non-binary or executable file type ({0}). Skipping: {1}'.format(mimeType, filePath))
        cleanUp(filePath)
        return False

    logging.info('File with hash: {0} identified as type: {1}'.format(fileHash, mimeType))

    uploaded = uploadToViper(filePath, fileName, fileUrl)

    addToHashCache(fileHash)
    cleanUp(filePath)

    return uploaded


def addToHashCache(fileHash):
    logging.info('Adding to cache: {0}'.format(fileHash))

    cache_file = os.path.join(rootDir, 'res', 'hashcache.txt')

    with open(cache_file, 'a') as out_file:
        out_file.write('{0}\n'.format(fileHash))


def addToUrlCache(fileUrl):
    logging.info('Adding to cache: {0}'.format(fileUrl))

    cache_file = os.path.join(rootDir, 'res', 'urlcache.txt')

    with codecs.open(cache_file, 'a', encoding='utf-8') as out_file:
        out_file.write('{0}\n'.format(fileUrl))


def isAcceptedHash(fileHash):
    cache_file = os.path.join(rootDir, 'res', 'hashcache.txt')
    exclude_file = os.path.join(rootDir, 'res', 'exclude.txt')

    cache_data = open(cache_file, 'r').read()
    
    if cache_data.count(fileHash) >= int(baseConfig.hashCountLimit):
        logging.info('There are already {0} instances of: {1}'.format(baseConfig.hashCountLimit, fileHash))
        return False

    if fileHash in open(exclude_file, 'r').read():
        logging.info('Hash is in exclude list: {0}'.format(fileHash))
        return False
    
    return True


def isAcceptedUrl(fileUrl):
    cache_file = os.path.join(rootDir, 'res', 'urlcache.txt')

    if fileUrl in codecs.open(cache_file, 'r', encoding='utf-8').read():
        logging.info('Existing or dead URL: {0}'.format(fileUrl))
        return False

    if len(fileUrl) > int(baseConfig.urlCharLimit):
        logging.info('URL exceeds configured limit: {0}'.format(fileUrl))
        addToUrlCache(fileUrl)
        return False
    
    return True


def cleanUp(filePath):
    if baseConfig.deleteOutput.lower() == 'yes' and os.path.exists(filePath):
        logging.info('Removing file: {0}'.format(filePath))
        os.remove(filePath)
