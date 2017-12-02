#!/usr/bin/python
from ConfigParser import SafeConfigParser


import os


class baseObj:
    def __init__(self, multiProcess, userAgent, outputFolderName, outputFolder, deleteOutput, dateFormat, torPort, redirectLimit, hashCountLimit, urlCharLimit, osintDays, malShareApiKey, disableMalShare, otxKey, vtKey, vtUser, viperUrlAdd, viperUrlFind, viperAddTags):
        self.multiProcess = multiProcess
        self.userAgent = userAgent
        self.outputFolderName = outputFolderName
        self.outputFolder = outputFolder
        self.deleteOutput = deleteOutput
        self.dateFormat = dateFormat
        self.torPort = torPort
        self.redirectLimit = redirectLimit
        self.hashCountLimit = hashCountLimit
        self.urlCharLimit = urlCharLimit
        self.osintDays = osintDays
        self.malShareApiKey = malShareApiKey
        self.disableMalShare = disableMalShare
        self.otxKey = otxKey
        self.vtKey = vtKey
        self.vtUser = vtUser
        self.viperUrlAdd = viperUrlAdd
        self.viperUrlFind = viperUrlFind
        self.viperAddTags = viperAddTags


def getBaseConfig(rootDir):
    parser = SafeConfigParser()
    parser.read(os.path.join(rootDir, 'config', 'settings.conf'))

    multiProcess = parser.get('Core', 'multiprocess')
    userAgent = parser.get('Core', 'useragent')
    outputFolderName = parser.get('Core', 'outputfolder')
    outputFolder = os.path.join(rootDir, outputFolderName)
    deleteOutput = parser.get('Core', 'deleteoutput')
    dateFormat = parser.get('Core', 'dateformat')
    torPort = parser.get('Core', 'torport')
    redirectLimit = parser.get('Core', 'redirectlimit')
    hashCountLimit = parser.get('Core', 'hashcountlimit')
    urlCharLimit = parser.get('Core', 'urlcharlimit')
    osintDays = parser.get('Core', 'osintdays')
    malShareApiKey = parser.get('MalShare', 'apikey')
    disableMalShare = parser.get('MalShare', 'disable')
    otxKey = parser.get('OTX', 'apikey')
    vtKey = parser.get('VirusTotal', 'apikey')
    vtUser = parser.get('VirusTotal', 'username')
    viperUrlAdd = parser.get('Viper', 'addurl')
    viperUrlFind = parser.get('Viper', 'findurl')
    viperAddTags = parser.get('Viper', 'addtags')

    return baseObj(multiProcess, userAgent, outputFolderName, outputFolder, deleteOutput, dateFormat, torPort, redirectLimit, hashCountLimit, urlCharLimit, osintDays, malShareApiKey, disableMalShare, otxKey, vtKey, vtUser, viperUrlAdd, viperUrlFind, viperAddTags)
