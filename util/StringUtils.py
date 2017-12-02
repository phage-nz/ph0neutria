#!/usr/bin/python
from BeautifulSoup import BeautifulSoup as bs
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger
from urlparse import urlparse, urljoin


import hashlib
import os
import random
import requests
import socket
import string 
import urllib2
import validators


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


stopword_file = os.path.join(rootDir, 'res', 'stopwords.txt')

stopword_list = []
with open(stopword_file, 'r') as in_file:
    stopword_list = in_file.read().splitlines()


def cleanUrl(url):
    if '??' in url:
        url = url.split('??')[0]

    if url.endswith('?'):
        url = url[:-1]

    return url


def containsNoStopwords(in_string):
    if any(s in in_string for s in stopword_list):
        return False
    return True


def getHostFromUrl(fileUrl):
    hostname = urlparse(fileUrl).hostname

    if ':' in hostname:
        hostname = hostname.split(':')[0]

    return hostname


def isValidIP(inString):
    try:
        socket.inet_aton(inString)
        return True
    except:
        return False


def isValidUrl(url):
    return validators.url(url)

def md5SumFile(fileName):
    with open(fileName) as fileToHash:
        data = fileToHash.read()
        md5Sum = hashlib.md5(data).hexdigest()
    return md5Sum


def md5SumString(inString):
    hasher = hashlib.md5()
    hasher.update(inString)
    return hasher.hexdigest()


def randomString(length):
   return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(length))


def soupParse(url):
	request = urllib2.Request(url)
	request.add_header('User-Agent', baseConfig.userAgent)
	try:
		http = bs(urllib2.urlopen(request))
	except:
		logging.error('Error parsing: {0}'.format(url))
		return
	return http
