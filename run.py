#!/usr/bin/env python
from __future__ import print_function

import multiprocessing
import os
import threading

from util.ConfigUtils import getBaseConfig
from util.CrimeTracker import getCrimeList
from util.DnsBlUtils import getBLList
from util.FileUtils import getWildFile, isAcceptedUrl
from util.LogUtils import getModuleLogger
from util.Malc0de import getMalc0deList
from util.MalShare import getMalShareList
from util.OtxUtils import getOTXList
from util.PayloadUtils import getPLList
from util.ShodanUtils import getShodanList
from util.VxVault import getVXList

#       .__    _______                        __         .__
#______ |  |__ \   _  \   ____   ____  __ ___/  |________|__|____
#\____ \|  |  \/  /_\  \ /    \_/ __ \|  |  \   __\_  __ \  \__  \
#|  |_> >   Y  \  \_/   \   |  \  ___/|  |  /|  |  |  | \/  |/ __ \_
#|   __/|___|  /\_____  /___|  /\___  >____/ |__|  |__|  |__(____  /
#|__|        \/       \/     \/     \/                           \/
#
#                  ph0neutria malware crawler
#                            v0.9.0
#             https://github.com/phage-nz/ph0neutria


rootDir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(rootDir, 'res', 'banner.txt'), 'r') as banner:
        print(banner.read())


logging = getModuleLogger(__name__)
baseConfig = getBaseConfig(rootDir)


def main():
    if not os.path.exists(baseConfig.outputFolder):
        os.makedirs(baseConfig.outputFolder)

    if baseConfig.multiProcess.lower() == 'yes':
        logging.info('Spawning multiple ph0neutria spiders. Press CTRL+C to terminate.')
        webs = []

        malc0deWeb = multiprocessing.Process(target=startMalc0de)
        vxVaultWeb = multiprocessing.Process(target=startVXVault)
        osintWeb = multiprocessing.Process(target=startOSINT)

        webs.append(malc0deWeb)
        webs.append(vxVaultWeb)
        webs.append(osintWeb)

        malc0deWeb.start()
        vxVaultWeb.start()

        if baseConfig.disableMalShare.lower() == 'no':
            malshareWeb = multiprocessing.Process(target=startMalShare)
            webs.append(malshareWeb)
            malshareWeb.start()

        if baseConfig.disableOsint.lower() == 'no':
            osintWeb.start()

        try:
            for web in webs:
                web.join()
        except KeyboardInterrupt:
            logging.info('Mother spider received Ctrl+C. Killing babies.')
            for web in webs:
                web.terminate()
                web.join()

    else:
        logging.info('Spawning single ph0neutria spider. Press CTRL+C to terminate.')
        startMalc0de()
        startVXVault()

        if baseConfig.disableMalShare.lower() == 'no':
            startMalShare()

        if baseConfig.disableOsint.lower() == 'no':
            startOSINT()


def startMalc0de():
    for mUrl in getMalc0deList():
        if isAcceptedUrl(mUrl):
            getWildFile(mUrl)


def startMalShare():
    for mUrl in getMalShareList():
        if isAcceptedUrl(mUrl):
            getWildFile(mUrl)


def startVXVault():
    for vUrl in getVXList():
        if isAcceptedUrl(vUrl):
            getWildFile(vUrl)


def startOSINT():
    pl_list = getPLList()

    if len(pl_list) > 0 and baseConfig.multiProcess.lower() == 'yes':
        pl_thread = threading.Thread(target=fetchOSINT, args=[pl_list])
        pl_thread.start()
        pl_thread.join()

    if len(pl_list) > 0 and baseConfig.multiProcess.lower() == 'no':
        fetchOSINT(pl_list)

    if len(pl_list) > 0 and baseConfig.multiProcess.lower() == 'no':
        fetchOSINT(pl_list)

    crime_list = getCrimeList()

    if len(crime_list) > 0 and baseConfig.multiProcess.lower() == 'yes':
        crime_thread = threading.Thread(target=fetchOSINT, args=[crime_list])
        crime_thread.start()
        crime_thread.join()

    if len(crime_list) > 0 and baseConfig.multiProcess.lower() == 'no':
        fetchOSINT(crime_list)

    otx_list = getOTXList()

    if len(otx_list) > 0 and baseConfig.multiProcess.lower() == 'yes':
        otx_thread = threading.Thread(target=fetchOSINT, args=[otx_list])
        otx_thread.start()
        otx_thread.join()

    if len(otx_list) > 0 and baseConfig.multiProcess.lower() == 'no':
        fetchOSINT(otx_list)

    shodan_list = getShodanList()

    if len(shodan_list) > 0 and baseConfig.multiProcess.lower() == 'yes':
        shodan_thread = threading.Thread(target=fetchOSINT, args=[shodan_list])
        shodan_thread.start()
        shodan_thread.join()

    if len(shodan_list) > 0 and baseConfig.multiProcess.lower() == 'no':
        fetchOSINT(shodan_list)

    if baseConfig.disableVT.lower() == 'no':
        bl_list = getBLList()
    else:
        bl_list = []

    if len(bl_list) > 0 and baseConfig.multiProcess.lower() == 'yes':
        bl_thread = threading.Thread(target=fetchOSINT, args=[bl_list])
        bl_thread.start()
        bl_thread.join()

    if len(bl_list) > 0 and baseConfig.multiProcess.lower() == 'no':
        fetchOSINT(bl_list)


def fetchOSINT(url_list):
    logging.info('Spawned new OSINT spider.')

    for oUrl in url_list:
        if isAcceptedUrl(oUrl):
            getWildFile(oUrl)


if __name__ == '__main__':
    main()
