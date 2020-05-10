#!/usr/bin/python3

from core.class_utils import MalwareHost
from core.config_utils import get_base_config
from core.log_utils import get_module_logger
from core.virus_total import get_class_for_hash


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


TYPES = ['malware-host']
NAME = 'Hybrid Analysis'
DISABLED = False


API_KEY = 'YOUR API KEY'
REQ_MIN = 5
SCORE_MIN = 100


HYBRID_WAIT = int(float(60) / REQ_MIN)


def is_blacklisted_family(family, tags):
    """Determines if a malware family is blacklisted.

    Params:
    family: (type: string) malware family.
    tags: (type: string list) list of recorded tags.

    Returns:
    - result: (type: bool) if family is blacklisted.
    """
    if len(BASECONFIG.blacklisted_tags) > 0:
        if family is not None:
            family = family.lower()

        for blacklisted_tag in BASECONFIG.blacklisted_tags:
            if family is not None:
                if blacklisted_tag in family:
                    return blacklisted_tag

            if tags is not None:
                if blacklisted_tag in tags:
                    return blacklisted_tag

    return False


def get_hybrid_reports():
    """Gets a list of recent reports from Hybrid Analysis.

    Returns:
    - result: (type: string list) list of valid report IDs.
    """
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'user-agent': 'Falcon Sandbox',
        'api-key': API_KEY}

    LOGGING.info('Fetching recent Hybrid Analysis items...')
    request = requests.get('https://www.hybrid-analysis.com/api/v2/feed/latest',
        headers=headers)

    LOGGING.info('Waiting for a moment...')
    time.sleep(HYBRID_WAIT)

    if request.status_code == 200:
        response = json.loads(request.text)

        report_list = []

        if response['count'] > 0:
            for report in response['data']:
                if 'vx_family' not in report:
                    continue

                family = report['vx_family']

                if family is not None:
                    if is_blacklisted_family(family, None):
                        continue

                if report['threat_score'] >= SCORE_MIN:
                    LOGGING.info(
                        'Discovered malware sample: {0}'.format(
                            report['sha256']))
                    report_list.append(report['job_id'])

        return report_list

    else:
        LOGGING.critical('Failed to query Hybrid Analysis.')
        LOGGING.warning(request.text)

    return []


def get_hybrid_report(job_id):
    """Gets a list of valid malware hosts from a report.

    Params:
    jobid: (type: string) job ID.

    Returns:
    - malware_hosts: (type: MalwareHost list) list of malware hosts.
    """
    headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': API_KEY}

    LOGGING.info('Fetching Hybrid Analysis report: {0}'.format(job_id))
    request = requests.get(
        'https://www.hybrid-analysis.com/api/v2/report/{0}/summary'.format(job_id),
        headers=headers)

    LOGGING.info('Waiting for a moment...')
    time.sleep(HYBRID_WAIT)

    if request.status_code == 200:
        response = json.loads(request.text)

        sha256 = response['sha256']
        family = response['vx_family']
        tags = response['classification_tags']
        extracted_files = response['extracted_files']

        blacklisted_sample = is_blacklisted_family(family, tags)

        if blacklisted_sample:
            LOGGING.warning(
                'Sample is blacklisted: {0} (term: {1})'.format(
                    sha256, blacklisted_sample))
            return []

        if extracted_files is not None:
            for extracted_file in extracted_files:
                av_label = extracted_file['av_label']
                file_sha256 = extracted_file['sha256']

                if av_label is not None:
                    blacklisted_file = is_blacklisted_family(av_label, None)

                    if blacklisted_file:
                        LOGGING.warning(
                            'Dropped file is blacklisted: {0} (term: {1})'.format(
                                file_sha256, blacklisted_file))
                        return []

        hosts = response['hosts']

        if len(hosts) > 0:
            malware_hosts = []

            av_class = get_class_for_hash(sha256)

            if av_class:
                blacklisted_class = is_blacklisted_family(av_class, None)

                if blacklisted_class:
                    LOGGING.warning('Sample is blacklisted: {0} (term: {1})'.format(
                        sha256, blacklisted_class))
                    return []

                for host in response['hosts']:
                    LOGGING.info(
                        'Discovered malware host: {0} ({1})'.format(
                            host, av_class))

                    malware_host = MalwareHost(
                        host, sha256, NAME)
                    malware_hosts.append(malware_host)

                if len(malware_hosts) > 0:
                    return malware_hosts

    else:
        LOGGING.critical('Failed to query Hybrid Analysis.')
        LOGGING.warning(request.text)

    return []


def get_malwarehost_list():
    """Gets a list of malware hosts from recent Hybrid Analysis reports.

    Returns:
    - malware_hosts: (type: MalwareHost list) list of malware hosts.
    """
    reports = get_hybrid_reports()

    if len(reports) > 0:
        malware_hosts = []

        for report in reports:
            report_hosts = get_hybrid_report(report)

            if len(report_hosts) > 0:
                malware_hosts.extend(report_hosts)

        if len(malware_hosts) > 0:
            return malware_hosts

    return []
