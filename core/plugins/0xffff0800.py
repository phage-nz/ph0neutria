#!/usr/bin/python3

from core.class_utils import MalwareUrl
from core.config_utils import get_base_config
from core.log_utils import get_module_logger
from core.web_utils import get_file_url_list


import os


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TYPES = ['malware-url']
NAME = '@0xffff0800 Library'
DISABLED = False


ROOT_URL = 'http://iec56w4ibovnb4wc.onion/Library/'


def get_malwareurl_list():
    """Produce a list of malware URLs from the APT malware sample library.

    Returns:
    - return_list: (type: MalwareUrl list) list of malware URLs.
    """
    url_list = get_file_url_list(ROOT_URL)

    if len(url_list) > 0:
        return_list = []

        for url in url_list:
            LOGGING.info(
                'Discovered sample URL: {0}'.format(url))

            return_list.append(
                MalwareUrl(
                    'iec56w4ibovnb4wc.onion',
                    '255.255.255.255',
                    url,
                    NAME))

        return return_list

    else:
        LOGGING.warning('Did not discover any samples.')

    return []
