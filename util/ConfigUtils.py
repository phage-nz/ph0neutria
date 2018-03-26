#!/usr/bin/python
from ConfigParser import SafeConfigParser


import os
import string


class baseObj:
    def __init__(self, multiProcess, userAgent, outputFolderName, outputFolder, deleteOutput, dateFormat, torIP, torPort, redirectLimit, hashCountLimit, urlCharLimit, osintDays, malShareApiKey, disableMalShare, disableOsint, otxKey, shodanKey, vtKey, vtUser, vtReqPerMin, viperUrlAdd, viperApiToken):
        self.multiProcess = multiProcess
        self.userAgent = userAgent
        self.outputFolderName = outputFolderName
        self.outputFolder = outputFolder
        self.deleteOutput = deleteOutput
        self.dateFormat = dateFormat
        self.torIP = torIP 
        self.torPort = torPort
        self.redirectLimit = redirectLimit
        self.hashCountLimit = hashCountLimit
        self.urlCharLimit = urlCharLimit
        self.osintDays = osintDays
        self.malShareApiKey = malShareApiKey
        self.disableMalShare = disableMalShare
        self.disableOsint = disableOsint
        self.otxKey = otxKey
        self.shodanKey = shodanKey
        self.vtKey = vtKey
        self.vtUser = vtUser
        self.vtReqPerMin = vtReqPerMin
        self.viperUrlAdd = viperUrlAdd
        self.viperApiToken = 'Token {0}'.format(viperApiToken)


def getBaseConfig(rootDir):
    parser = SafeConfigParser()
    parser.read(os.path.join(rootDir, 'config', 'settings.conf'))

    multiProcess = parser.get('Core', 'multiprocess')
    userAgent = parser.get('Core', 'useragent')
    outputFolderName = parser.get('Core', 'outputfolder')
    outputFolder = os.path.join(rootDir, outputFolderName)
    deleteOutput = parser.get('Core', 'deleteoutput')
    dateFormat = parser.get('Core', 'dateformat')
    torIP = parser.get('Core', 'torip')
    torPort = parser.get('Core', 'torport')
    redirectLimit = parser.get('Core', 'redirectlimit')
    hashCountLimit = parser.get('Core', 'hashcountlimit')
    urlCharLimit = parser.get('Core', 'urlcharlimit')
    osintDays = parser.get('Core', 'osintdays')
    malShareApiKey = parser.get('MalShare', 'apikey')
    disableMalShare = parser.get('MalShare', 'disable')
    disableOsint = parser.get('OSINT', 'disable')
    otxKey = parser.get('OTX', 'apikey')
    shodanKey = parser.get('Shodan', 'apikey')
    vtKey = parser.get('VirusTotal', 'apikey')
    vtUser = parser.get('VirusTotal', 'username')
    vtReqPerMin = parser.get('VirusTotal', 'requestsperminute')
    viperUrlAdd = parser.get('Viper', 'addurl')
    viperApiToken = parser.get('Viper', 'apitoken')

    return baseObj(multiProcess, userAgent, outputFolderName, outputFolder, deleteOutput, dateFormat, torIP, torPort, redirectLimit, hashCountLimit, urlCharLimit, osintDays, malShareApiKey, disableMalShare, disableOsint, otxKey, shodanKey, vtKey, vtUser, vtReqPerMin, viperUrlAdd, viperApiToken)
