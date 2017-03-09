#!/usr/bin/python
from BeautifulSoup import BeautifulSoup as bs
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
import hashlib
import os
import random
import requests
import string 
import urllib2
import validators

cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)

def soupParse(url):
	request = urllib2.Request(url)
	request.add_header('User-Agent', baseConfig.userAgent)
	try:
		http = bs(urllib2.urlopen(request))
	except:
		logging.error("Error parsing: {0}".format(url))
		return
	return http

def isValidUrl(url):
    return validators.url(url)

def randomString(length):
   return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(length))

def md5SumFile(fileName):
    with open(fileName) as fileToHash:
        data = fileToHash.read()
        md5Sum = hashlib.md5(data).hexdigest()
    return md5Sum

def md5SumString(inString):
    hasher = hashlib.md5()
    hasher.update(inString)
    return hasher.hexdigest()
