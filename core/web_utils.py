#!/usr/bin/python3

from .config_utils import get_base_config
from .log_utils import get_module_logger
from .string_utils import get_host_from_url
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


import os
import requests
import sys


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


BAD_CHARS = ['*', '?']
ALLOWED_EXTENSIONS = ['.doc', '.xls', '.docx', '.xlsx', '.bin', '.dll', '.exe', '.gz', '.rar', '.zip']


def build_folder_map(base_url, proxies):
    """Request base_url and extract all relevant href values from the page.

   Target page must be a folder listing.

    Params:
    - base_url: (type: string) URL to query.
    - proxies: (type: JSON object) HTTP and HTTPS proxy values.

    Returns:
    - children: (type: string list) list of URLs.
    """
    try:
        LOGGING.info('Requesting: {0}'.format(base_url))

        request = requests.get(base_url, proxies=proxies, timeout=(20, 20))

        if request.status_code == 200:
            LOGGING.info('Request OK. Parsing result...')

            children = []

            content = BeautifulSoup(request.text, 'html.parser')
            links = content.find_all('a', href=True)

            for link in links:
                if 'Parent Directory' in link:
                    continue

                href = link.get('href')

                if len(href) > 1 and not any(s in href for s in BAD_CHARS):
                    children.append(urljoin(base_url, href))

            return children

        else:
            LOGGING.warning(
                'Problem connecting to {0}. Status code: {1}. Aborting task.'.format(
                    base_url, request.status_code))

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning(
            'Problem connecting to {0}. Error: {1}'.format(
                base_url, e))

    except Exception as e:
        LOGGING.warning(
            'Problem connecting to {0}. Aborting task.'.format(base_url))
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return []


def process_list(entity_list):
    """Split a list of URLs into folder and file lists.

    Params:
    - entity_url: (type: string list) raw list of URLs.

    Returns:
    - folder_list: (type: string list) list of folder URLs.
    - file_list: (type: string list) list of file URLs.
    """
    LOGGING.info('Processing returned entities...')

    folder_list = []
    file_list = []

    for entity in entity_list:
        entity_parts = os.path.split(urlparse(entity).path)

        if entity_parts[1] == '':
            folder_list.append(entity)

        else:
            if any(entity_parts[1].endswith(ext) for ext in ALLOWED_EXTENSIONS):
                file_list.append(entity)

    return folder_list, file_list


def get_file_url_list(root_url):
    """Initiates a spider across an open directory listing.

    Params:
    - root_url: (type: string list) (type: string) URL to query.

    Returns:
    - file_list: (type: string list) list of file URLs.
    """
    LOGGING.info('Starting spider...')

    proxies = {
        'http': '',
        'https': ''
    }

    if get_host_from_url(root_url).endswith('.onion'):
        if not BASECONFIG.use_tor:
            LOGGING.warning('.onion source requires Tor to be enabled.')
            return []

        LOGGING.info('Requests will be made over the Tor network.')

        proxies = {
            'http': 'socks5h://{0}:{1}'.format(BASECONFIG.tor_ip, int(BASECONFIG.tor_port)),
            'https': 'socks5h://{0}:{1}'.format(BASECONFIG.tor_ip, int(BASECONFIG.tor_port))
        }

    initial_list = build_folder_map(root_url, proxies)
    folder_list, file_list = process_list(initial_list)

    if len(folder_list) > 0:
        while len(folder_list) > 0:
            for folder in folder_list:
                child_list = build_folder_map(folder, proxies)
                child_folders, child_files = process_list(child_list)

                if len(child_files) > 0:
                    file_list.extend(child_files)

                if len(child_folders) > 0:
                    folder_list.extend(child_folders)

                folder_list.remove(folder)

    LOGGING.info('Spider completed. Discovered {0} files:'.format(len(file_list)))

    return file_list
