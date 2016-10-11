#!/usr/bin/python
import coloredlogs
import logging

def getModuleLogger(moduleName):
    logger = logging.getLogger(moduleName)
    logger.setLevel(logging.INFO)
    coloredlogs.install(level='INFO')
    return logger
