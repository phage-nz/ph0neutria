#!/usr/bin/python3

from .config_utils import get_base_config
from .log_utils import get_module_logger
from .malware_utils import get_malware_urls, queue_malware_list


import os
import sys
import threading


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


def start_core():
    """Initiate core tasks."""
    with open(os.path.join(ROOTDIR, 'res', 'banner.txt'), 'r') as banner:
        print(banner.read())

    LOGGING.info('Finding victims to bring to the nest to play...')

    mal_url_list = get_malware_urls()
    queue_malware_list(mal_url_list)

    LOGGING.info('Our work today is complete, but there will be more victims tomorrow.')
