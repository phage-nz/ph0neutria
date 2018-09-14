#!/usr/bin/python3

from .config_utils import get_base_config
from .log_utils import get_module_logger
from .string_utils import similar_string_fast


import os
import sys
import validators


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


SCORE_THRESHOLD_NORMAL = 100
SCORE_THRESHOLD_FAST = 90


# This is ugly. Need to refactor it.
def filter_url_list(url_list):
    """Filter out identical and similar items in a URL list.

    Params:
    - url_list: (type: MalwareUrl/PhishingListEntry/PhishingUrl list) URL object list.

    Returns:
    - return_list: (type: MalwareUrl/PhishingListEntry/PhishingUrl list) filtered URL object list.
    """
    LOGGING.info('Filtering URL list...')
    LOGGING.info('Before: {0}'.format(len(url_list)))

    staging_list = []
    unique_list = []

    for url_object in url_list:
        staging_list.append(url_object.url)

    for in_url in staging_list:
        if in_url not in unique_list:
            insert = True

            for unique_url in unique_list:
                if similar_string_fast(in_url, unique_url):
                    insert = False

            if insert:
                unique_list.append(in_url)

    return_list = []

    for url_object in url_list:
        if url_object.url in unique_list:
            unique_list.remove(url_object.url)
            return_list.append(url_object)

    LOGGING.info('After: {0}'.format(len(return_list)))
    LOGGING.info('Filtering complete!')

    return return_list


def filter_ip_list(ip_list):
    """Filter out identical addresses in an IP address list.

    Params:
    - ip_list: (type: string list) IP address list.

    Returns:
    - return_list: (type: string list) filtered IP address list.
    """
    LOGGING.info('Filtering IP list...')
    LOGGING.info('Before: {0}'.format(len(ip_list)))

    unique_list = list(set(ip_list))
    return_list = []

    for ip_addr in unique_list:
        if validators.ipv4(ip_addr):
            return_list.append(ip_addr)

    LOGGING.info('After: {0}'.format(len(return_list)))
    LOGGING.info('Filtering complete!')

    return return_list
