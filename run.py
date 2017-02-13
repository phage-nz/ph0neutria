#!/usr/bin/python
from util.ConfigUtils import getBaseConfig
from util.FileUtils import getWildFile
from util.LogUtils import getModuleLogger
from util.Malc0de import getMalc0deList
from util.MalShare import getMalShareDigest, getMalShareList, getMalShareSource, getMalShareFile
from util.Minotaur import getMinotaurList
from util.StringUtils import md5SumString
from util.ViperUtils import isNewEntry
from util.VxVault import getVXList
import multiprocessing
import os

#       .__    _______                        __         .__       
#______ |  |__ \   _  \   ____   ____  __ ___/  |________|__|____  
#\____ \|  |  \/  /_\  \ /    \_/ __ \|  |  \   __\_  __ \  \__  \ 
#|  |_> >   Y  \  \_/   \   |  \  ___/|  |  /|  |  |  | \/  |/ __ \_
#|   __/|___|  /\_____  /___|  /\___  >____/ |__|  |__|  |__(____  /
#|__|        \/       \/     \/     \/                           \/
#
#                  ph0neutria malware crawler
#                            v0.6.0
#             https://github.com/phage-nz/ph0neutria

rootDir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(rootDir, 'res', 'banner.txt'), 'r') as banner:
        print banner.read()

logging = getModuleLogger(__name__)
baseConfig = getBaseConfig(rootDir)

def main(): 
    if not os.path.exists(baseConfig.outputFolder):
        os.makedirs(baseConfig.outputFolder)

    if baseConfig.multiProcess.lower() == "yes":
        logging.info("Spawning multiple ph0neutria processes. Press CTRL+C to terminate.")
        webs = []
        malc0deWeb = multiprocessing.Process(target=startMalc0de)
        minotaurWeb = multiprocessing.Process(target=startMinotaur)
        vxVaultWeb = multiprocessing.Process(target=startVXVault)
        webs.append(malc0deWeb)
        webs.append(minotaurWeb)
        webs.append(vxVaultWeb)
        malc0deWeb.start()
        minotaurWeb.start()
        vxVaultWeb.start()

        if baseConfig.disableMalShare.lower() == "no":
            malshareWeb = multiprocessing.Process(target=startMalShare)
            webs.append(malshareWeb)
            malshareWeb.start()

        try:
            for web in webs:
                web.join()
        except KeyboardInterrupt:
            logging.info("Mother spider received Ctrl+C. Killing babies.")
            for web in webs:
                web.terminate()
                web.join()
                
    else:
        logging.info("Spawning single ph0neutria process. Press CTRL+C to terminate.")
        startMalc0de()
        startMinotaur()
        startVXVault()

        if baseConfig.disableMalShare.lower() == "no":
            startMalShare()

def startMalc0de():
    for mUrl in getMalc0deList():
        mUrlHash = md5SumString(mUrl)
        if isNewEntry(urlHash=mUrlHash):
            logging.info("Downloading from the wild: {0}".format(mUrl))
            getWildFile(mUrl, mUrlHash)

def startMinotaur():
    for mUrl in getMinotaurList():
        mUrlHash = md5SumString(mUrl)
        if isNewEntry(urlHash=mUrlHash):
            logging.info("Downloading from the wild: {0}".format(mUrl))
            getWildFile(mUrl, mUrlHash)

def startMalShare():
    if baseConfig.malShareRemoteOnly.lower() == "yes":
        for mUrl in getMalShareList():
            mUrlHash = md5SumString(mUrl)
            if isNewEntry(urlHash=mUrlHash):
                logging.info("Downloading from the wild: {0}".format(mUrl))
                getWildFile(mUrl, mUrlHash)

    else:
        for mHash in getMalShareDigest():
            if isNewEntry(fileHash=mHash):
                if baseConfig.malShareRemoteFirst.lower() == "yes":
                    mUrl = getMalShareSource(mHash)
                    mUrlHash = md5SumString(mUrl)
                    logging.info("Attempting remote download first: {0}".format(mUrl))
                    if isNewEntry(urlHash=mUrlHash):
                        if not getWildFile(mUrl, mUrlHash):
                            logging.info("Remote download failed. Downloading from MalShare: {0}".format(mHash))
                            getMalShareFile(mHash)
                else:
                    logging.info("Downloading from MalShare: {0}".format(mHash))
                    getMalShareFile(fileHash)

def startVXVault():
    for vUrl in getVXList():
        print vUrl
        vUrlHash = md5SumString(vUrl)
        if isNewEntry(urlHash=vUrlHash):
            logging.info("Downloading from the wild: {0}".format(vUrl))
            getWildFile(vUrl, vUrlHash)

if __name__ == "__main__":
    main()
