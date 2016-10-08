#!/usr/bin/python
from BeautifulSoup import BeautifulSoup as bs
import hashlib
import random
import requests
import string 
import urllib2

def convert2printable(s):
    if not isinstance(s, basestring) or isPrintable(s):
        return s
    return "".join(convertChar(c) for c in s)

def isPrintable(s):
    for c in s:
        if not c in PRINTABLE_CHARACTERS:
            return False
    return True

def soupParse(url):
	request = urllib2.Request(url)
	request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
	try:
		http = bs(urllib2.urlopen(request))
	except:
		print "- Error parsing %s" % (url)
		return
	return http

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
