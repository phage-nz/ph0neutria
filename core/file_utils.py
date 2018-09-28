#!/usr/bin/python3

from .config_utils import get_base_config
from .crypto_utils import hash_file, random_string
from .log_utils import get_module_logger
from urllib.parse import urljoin, urlparse


import codecs
import json
import magic
import os
import requests
import sys
import validators


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


# TOR proxy
if BASECONFIG.use_tor:
    proxies = {
        'http': 'socks5://{0}:{1}'.format(BASECONFIG.tor_ip, int(BASECONFIG.tor_port)),
        'https': 'socks5://{0}:{1}'.format(BASECONFIG.tor_ip, int(BASECONFIG.tor_port))
    }

else:
    proxies = {
        'http': '',
        'https': ''
    }


def profile_url_file(listed_url):
    """Determine the file hash and type of a URL payload.

    Params:
    - listed_url: (type: string) URL to query.

    Returns:
    - file_hash: (type: string) SHA256 hash of file.
    - is_binary: (type: string) MIME type of file.
    """
    if not is_accepted_url(listed_url):
        return False

    add_to_url_cache(listed_url)

    file_url, prestage_ok, abort_get = head_request(listed_url)

    if prestage_ok and abort_get == False and file_url != listed_url:
        attempts = 2

        while attempts <= int(
                BASECONFIG.redirect_limit) and prestage_ok == False and abort_get == False:
            file_url, prestage_ok = head_request(file_url)
            attempts += 1

        if prestage_ok:
            tmp_file_path = request_url(file_url)

            return tmp_file_path

        else:
            LOGGING.warning(
                'Encountered an error in pre-stage for URL: {0}'.format(file_url))

            return False

    elif prestage_ok:
        tmp_file_path = request_url(file_url)

        return tmp_file_path

    return False


def head_request(file_url):
    """Perform a HEAD request to assess whether it's viable to proceed.

    Params:
    - file_url: (type: string) URL to query.

    Returns:
    - file_url: (type: string) next URL to query if a redirect occurs.
    - prestage_ok: (type: bool) continue with next request.
    - abort_ok: (type: bool) terminate request due to error.
    """
    LOGGING.info('Making HEAD request to: {0}'.format(file_url))

    try:
        user_agent = {'User-agent': BASECONFIG.user_agent}

        head = requests.head(file_url, headers=user_agent, timeout=(20, 20))

        if head.status_code == 200:
            if 'Content-Length' in head.headers:
                file_size = int(head.headers['Content-Length']) >> 20

                if (file_size > 25):
                    LOGGING.error(
                        'File is {0}MB. Too large to bother processing.'.format(file_size))
                    return file_url, False, True

                else:
                    return file_url, True, False

            else:
                LOGGING.info(
                    'HEAD request to {0} did not return a Content-Length header. Attempting GET.'.format(file_url))
                return file_url, True, False

        elif head.status_code == 301 or head.status_code == 302:
            if 'Location' in head.headers:
                location_header = head.headers['Location']

                if validators.url(location_header):
                    file_url = head.headers['Location']

                else:
                    file_url = urljoin(file_url.rsplit(
                        '/', 0)[0], head.headers['Location'])

                return file_url, True, False

            else:
                LOGGING.info(
                    'HEAD request to {0} responded with a redirect without a location. Aborting task.'.format(file_url))
                return file_url, False, True

        elif head.status_code == 403:
            LOGGING.info(
                'HEAD request to {0} returned 403 (may not be permitted). Attempting GET.'.format(file_url))
            return file_url, True, False

        else:
            LOGGING.warning(
                'Problem connecting to {0}. Status code: {1}. Aborting task.'.format(
                    file_url, head.status_code))
            return file_url, False, True

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning(
            'Problem connecting to {0}. Error: {1}'.format(
                file_url, e))

        return file_url, False, True

    except Exception as e:
        LOGGING.warning(
            'Problem connecting to {0}. Aborting task.'.format(file_url))
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

        return file_url, False, True


def request_url(file_url):
    """Download the content of a URL and determine it's hash and type.

    Params:
    - file_url: (type: string) URL to query.

    Returns:
    - tmp_file_path: (type: string) location on disk of downloaded file.
    """
    try:
        user_agent = {'User-agent': BASECONFIG.user_agent}

        request = requests.get(file_url, headers=user_agent, timeout=(20, 20))

        if request.status_code == 200:
            response = request.content

            tmp_name = random_string(32)
            tmp_file_path = os.path.join(BASECONFIG.output_folder, tmp_name)
            file_name = urlparse(file_url).path.strip('/')

            with open(tmp_file_path, 'wb') as outfile:
                outfile.write(response)

            download_ok = process_download(tmp_file_path)

            if download_ok:
                return tmp_file_path

            return False

        else:
            LOGGING.warning(
                'Problem connecting to {0}. Status code: {1}. Aborting task.'.format(
                    file_url, request.status_code))
            return False

    except requests.exceptions.ConnectionError as e:
        LOGGING.warning(
            'Problem connecting to {0}. Error: {1}'.format(
                file_url, e))

    except Exception as e:
        LOGGING.warning(
            'Problem connecting to {0}. Aborting task.'.format(file_url))
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return False


def process_download(tmp_file_path):
    """Determine the file hash and type of a downloaded file.

    Params:
    - tmp_file_path: (type: string) file path of temporary file.

    Returns:
    - download_ok: (type: bool) whether the downloaded file is acceptable.
    """
    LOGGING.info(
        'Downloaded as temporary file: {0}. Beginning processing...'.format(tmp_file_path))

    file_hash = hash_file(tmp_file_path)

    if not is_accepted_hash(file_hash):
        clean_up(tmp_file_path)
        return False

    mime_type = magic.from_file(tmp_file_path, mime=True)

    LOGGING.info(
        'File with hash {0} identified as type: {1}'.format(
            file_hash, mime_type))

    if mime_type not in [
        'application/octet-stream',
        'application/x-dosexec',
        'application/x-msdownload',
        'application/x-ms-installer',
        'application/pdf',
        'application/x-pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
        'application/vnd.ms-word.document.macroEnabled',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
        'application/vnd.ms-excel.sheet.macroEnabled',
        'application/vnd.ms-excel.template.macroEnabled',
        'application/vnd.ms-excel.addin.macroEnabled',
        'application/vnd.ms-excel.sheet.binary.macroEnabled',
        'application/x-shockwave-flash',
        'application/zip',
        'text/rtf']:
        clean_up(tmp_file_path)
        return False

    add_to_hash_cache(file_hash)

    return True


def clean_up(file_path):
    """Removes a temporary file.

    Params:
    - file_path: (type: string) temporary file path.
    """
    if os.path.exists(file_path):
        LOGGING.info('Removing file: {0}'.format(file_path))
        os.remove(file_path)


def add_to_hash_cache(file_hash):
    LOGGING.info('Adding to cache: {0}'.format(file_hash))

    cache_file = os.path.join(ROOTDIR, 'data', 'hashcache.txt')

    with open(cache_file, 'a') as out_file:
        out_file.write('{0}\n'.format(file_hash))


def add_to_url_cache(file_url):
    LOGGING.info('Adding to cache: {0}'.format(file_url))

    cache_file = os.path.join(ROOTDIR, 'data', 'urlcache.txt')

    with codecs.open(cache_file, 'a') as out_file:
        out_file.write('{0}\n'.format(file_url))


def is_accepted_hash(file_hash):
    cache_file = os.path.join(ROOTDIR, 'data', 'hashcache.txt')
    exclude_file = os.path.join(ROOTDIR, 'data', 'exclude.txt')

    cache_data = open(cache_file, 'r').read()
    
    if cache_data.count(file_hash) >= int(BASECONFIG.hash_count_limit):
        LOGGING.info('There are already {0} instances of: {1}'.format(BASECONFIG.hash_count_limit, file_hash))
        return False

    if file_hash in open(exclude_file, 'r').read():
        LOGGING.info('Hash is in exclude list: {0}'.format(file_hash))
        return False
    
    return True


def is_accepted_url(file_url):
    cache_file = os.path.join(ROOTDIR, 'data', 'urlcache.txt')

    if file_url in codecs.open(cache_file, 'r').read():
        LOGGING.info('Existing or dead URL: {0}'.format(file_url))
        return False

    if len(file_url) > int(BASECONFIG.url_char_limit):
        LOGGING.info('URL exceeds configured limit: {0}'.format(file_url))
        add_to_url_cache(file_url)
        return False
    
    return True
