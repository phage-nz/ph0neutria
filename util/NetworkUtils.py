#!/usr/bin/python
from ConfigUtils import getBaseConfig
from LogUtils import getModuleLogger


import string 
import socket
import os


cDir = os.path.dirname(os.path.realpath(__file__))
rootDir = os.path.abspath(os.path.join(cDir, os.pardir))
baseConfig = getBaseConfig(rootDir)
logging = getModuleLogger(__name__)


def forwardLookup(hostname):
    try:
        data = socket.gethostbyname(hostname)
        return str(data)
    except:
        return '?'
