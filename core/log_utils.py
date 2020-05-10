#!/usr/bin/python3

import coloredlogs
import logging


def get_module_logger(moduleName):
    """Initialises a Logger object for a specific module.

    Params:
    - moduleName: (type: string) name of the calling module.

    Returns:
    - logger: (type: Logger) logging object.
    """
    logger = logging.getLogger(moduleName)
    logger.setLevel(logging.INFO)
    coloredlogs.install(level='INFO')
    return logger
