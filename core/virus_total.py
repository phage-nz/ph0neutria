#!/usr/bin/python3

from .class_utils import MalwareUrl
from .config_utils import get_base_config
from datetime import datetime, timedelta
from .log_utils import get_module_logger
from .string_utils import clean_url, get_host_from_url


import dateutil.parser
import json
import os
import requests
import sys
import time


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)

LOGGING = get_module_logger(__name__)

URL_WAIT = int(float(60) / BASECONFIG.vt_req_min)
CLASS_WAIT = URL_WAIT / BASECONFIG.malware_workers


def get_urls_for_ip(ip_addr, source):
    """Produce a list of malware URLs for an IP address.

    Params:
    - ip_addr: (type: string) IP address to query.
    - source: (type: string) source of IP address.

    Returns:
    - url_list: (type: MalwareUrl list) list of malware URLs.
    """
    params = {'apikey': BASECONFIG.vt_key, 'ip': ip_addr}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': BASECONFIG.vt_user}

    LOGGING.info(
        'Querying VirusTotal for URLs associated with: {0}'.format(ip_addr))
    response = requests.get(
        'https://www.virustotal.com/vtapi/v2/ip-address/report',
        params=params,
        headers=headers)

    LOGGING.info('Waiting for a moment...')
    time.sleep(URL_WAIT)

    if response.status_code == 200:
        vt_report = json.loads(response.text)

        if vt_report['response_code'] == 0:
            LOGGING.info('Address not found.')

        if vt_report['response_code'] == 1:
            if 'detected_urls' in vt_report:
                url_list = []

                for url in vt_report['detected_urls']:
                    if url['positives'] < BASECONFIG.vt_score_min:
                        continue

                    if dateutil.parser.parse(
                            url['scan_date']) > (
                            datetime.utcnow() -
                            timedelta(
                                days=BASECONFIG.malware_days)):
                        cleaned_url = clean_url(url['url'])

                        if cleaned_url is None:
                            continue

                        host_name = get_host_from_url(cleaned_url)

                        LOGGING.info(
                            'Discovered malicious URL: {0}'.format(cleaned_url))

                        url_list.append(
                            MalwareUrl(
                                host_name,
                                ip_addr,
                                cleaned_url,
                                'VirusTotal via {0}'.format(source)))

                return url_list

    else:
        LOGGING.critical('Failed to query VirusTotal.')
        LOGGING.warning(response.text)

    return []


def is_blacklisted_class(scans):
    """Determines whether the classification of a result is blacklisted.

    Params:
    - scans: (type: string list) list of VirusTotal scans.

    Returns:
    - blacklisted_tag: (type: string) name of blacklisted tag.
    """
    if len(BASECONFIG.blacklisted_tags) == 0:
        return False

    for engine in scans:
        if scans[engine]['detected']:
            sample_class = scans[engine]['result'].lower()

            for blacklisted_tag in BASECONFIG.blacklisted_tags:
                if blacklisted_tag in sample_class:
                    return blacklisted_tag

    return False


def get_class_from_scans(scans):
    """Determines the classification of a result.

    Params:
    - scans: (type: string list) list of VirusTotal scans.

    Returns:
    - result: (type: string) result classification.
    """
    for engine in BASECONFIG.vt_preferred_engines:
        if engine in scans:
            if scans[engine]['detected']:
                class_result = scans[engine]['result']
                LOGGING.info('Sample classified as: {0}'.format(class_result))
                return class_result

    LOGGING.warning('Unable to determine sample classification. Returning generic response.')

    return 'Malware.Generic'


def get_class_for_hash(file_hash):
    """Determines the classification of a file based on it's hash.

    Params:
    - file_hash: (type: string) SHA256 hash of file.

    Returns:
    - result: (type: string) file classification.
    """
    params = {'apikey': BASECONFIG.vt_key, 'resource': file_hash}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': BASECONFIG.vt_user}

    LOGGING.info(
        'Querying VirusTotal for classification associated with: {0}'.format(file_hash))
    response = requests.get(
        'https://www.virustotal.com/vtapi/v2/file/report',
        params=params,
        headers=headers)

    LOGGING.info('Waiting for a moment...')
    time.sleep(CLASS_WAIT)

    if response.status_code == 200:
        vt_report = json.loads(response.text)

        if vt_report['response_code'] == 0:
            LOGGING.info('File not found.')

        if vt_report['response_code'] == 1:
            if vt_report['positives'] < BASECONFIG.vt_score_min:
                LOGGING.warning('Potential false positive for sample: {0}'.format(file_hash))
                return False

            if 'scans' in vt_report:
                scans = vt_report['scans']

                blacklisted_sample = is_blacklisted_class(scans)

                if blacklisted_sample:
                    LOGGING.warning('Sample is blacklisted: {0} (term: {1})'.format(file_hash, blacklisted_sample))
                    return False

                return get_class_from_scans(scans)

            else:
                LOGGING.info('No scans for file.')

    else:
        LOGGING.critical('Failed to query VirusTotal.')
        LOGGING.warning(response.text)

    return False
