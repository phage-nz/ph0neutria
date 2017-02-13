#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from StringUtils import md5SumFile, randomString
from ViperUtils import getTags, uploadToViper, isNewEntry
import os
import requests
import sys

cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)

def getWildFile(url, urlMD5):
    try:
        userAgent = {'User-agent': baseConfig.userAgent}

        if baseConfig.useTor == 'yes':
            torProxy = 'socks5://localhost:{0}'.format(baseConfig.torPort)
            proxies = {'http': torProxy, 'https': torProxy}
            request = requests.get(url, headers=userAgent, proxies=proxies)
        else:
            request = requests.get(url, headers=userAgent)

        if request.status_code == 200:
            response = request.content

            tmpName = randomString(32)
            tmpFilePath = os.path.join(baseConfig.outputFolder, tmpName)
            open(tmpFilePath,"wb").write(response)
            logging.info("Saved as temporary file: {0}. Calculating MD5.".format(tmpFilePath))

            fileMD5 = md5SumFile(tmpFilePath)
            filePath = os.path.join(baseConfig.outputFolder, fileMD5)
            os.rename(tmpFilePath, filePath)
            logging.info("Renamed as file: {0}. Checking Viper again.".format(filePath))

            if isNewEntry(fileHash=fileMD5):
                fileName = url.split('/')[-1]
                tags = getTags(fileMD5, url, "wild-spider", urlHash=urlMD5)
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
            logging.warning("Problem connecting to {0}. Status code: {1}. Continuing.".format(url, request.status_code))
            return False

    except requests.exceptions.ConnectionError as e:
        logging.warning("Problem connecting to {0}. Error: {1}".format(url, e))
        return False

    except Exception as e:
        logging.warning("Problem connecting to {0}. Continuing.".format(url))
        logging.exception(sys.exc_info())
        logging.exception(type(e))
        logging.exception(e.args)
        logging.exception(e)
        return False
        #sys.exit(1)
