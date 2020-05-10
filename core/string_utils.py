#!/usr/bin/python3

from .config_utils import get_base_config
from fuzzywuzzy import fuzz
from .log_utils import get_module_logger
from tldextract import extract, TLDExtract
from urllib.parse import urlparse


import Levenshtein
import os
import re
import statistics
import string
import sys


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


SCORE_THRESHOLD_NORMAL = 100
SCORE_THRESHOLD_FAST = 90


def truncate_string(input_string, length):
    """Truncate a string.

    Params:
    - in_string: (type: string) string to truncate.
    - length: (type: int) length of output string.

    Returns:
    - result: (type: string) truncated string.
    """
    return (input_string[:length] +
            '..') if len(input_string) > 1024 else input_string


def clean_url(url):
    """Remove extraneous characters from URL.

    Params:
    - url: (type: string) URL to clean.

    Returns:
    - url: (type: string) clean URL.
    """

    if url is None:
        return None

    if '??' in url:
        url = url.split('??')[0]

    if url.endswith('?'):
        url = url[:-1]

    if '`' in url:
        url = url.replace('`', '')

    return url


def get_host_from_url(url):
    """Extract the host name from a URL.

    Params:
    - url: (type: string) URL to parse.

    Returns:
    - host_name: (type: string) host name.
    """
    host_name = urlparse(url).hostname

    if ':' in host_name:
        host_name = host_name.split(':')[0]

    return host_name


def remove_tld(domain):
    """Remove the TLD from a domain name.

    Params:
    - domain: (type: string) FQDN.

    Returns:
    - domain: (type: string) FQDN without TLD.
    """
    try:
        tld = extract(domain).suffix
        domain = ''.join(domain.rsplit(tld, 1)).strip('.')

    except Exception as e:
        LOGGING.warning(
            'Error stripping TLD ({0}): {1}'.format(
                domain, str(e)))

    return domain


def extract_address(input_string):
    """Extracts an IP address from a blob of text.

    Params:
    - input_string: (type: string) string to parse.

    Returns:
    - result: (type: string) extracted IP address.
    """
    if input_string:
        addr_search = re.search(
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)',
            input_string)

        if bool(addr_search):
            return addr_search.group()

    return None


def extract_url(input_string):
    """Extracts a URL from a blob of text.

    Params:
    - input_string: (type: string) string to parse.

    Returns:
    - result: (type: string) extracted URL.
    """
    if input_string:
        url_search = re.search(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            input_string)

        if bool(url_search):
            return url_search.group()

    return None


def fuzzy_score_string(first_string, second_string):
    """Produce a similarity score for two strings (using Levenshtein distance).

    Params:
    - first_string: (type: string) first string.
    - second_string: (type: string) second string.

    Returns:
    - result: (type: int) score.
    """
    score = 0

    if len(first_string) < len(second_string):
        shorter, longer = (first_string, second_string)
        window_length = len(shorter)

        num_iterations = len(longer) - len(shorter) + 1

        for position in range(0, num_iterations):
            window = longer[position:position + window_length]
            l_ratio = Levenshtein.ratio(window, shorter) * 100

            if l_ratio > 60:
                result = statistics.mean(
                    [100 - Levenshtein.distance(window, shorter) * 15, l_ratio, l_ratio])

            else:
                result = l_ratio

            if result > score:
                score = result

    else:
        l_ratio = Levenshtein.ratio(first_string, second_string) * 100
        score = statistics.mean(
            [100 - Levenshtein.distance(first_string, second_string) * 15, l_ratio, l_ratio])

    simple = fuzz.ratio(first_string, second_string)
    partial = fuzz.partial_ratio(first_string, second_string)
    sort = fuzz.token_sort_ratio(first_string, second_string)
    set_ratio = fuzz.token_set_ratio(first_string, second_string)

    score = max([score, simple, partial, sort, set_ratio])

    if score < 75:
        score = 0

    return score * 0.85


def score_match(first_string, second_string, domain_score=False):
    """Produce a similarity score for two strings.

    Params:
    - first_string: (type: string) first string.
    - second_string: (type: string) second string.
    - domain_score: (type: bool) whether the comparison is of two domains.

    Returns:
    - result: (type: int) score.
    """
    score = 0

    if first_string == second_string:
        return SCORE_THRESHOLD_NORMAL

    if domain_score:
        if remove_tld(first_string) == remove_tld(second_string):
            return SCORE_THRESHOLD_NORMAL

    if second_string in first_string:
        return SCORE_THRESHOLD_NORMAL

    if domain_score:
        first_string = remove_tld(first_string)
        second_string = remove_tld(second_string)

    l_distance = Levenshtein.distance(first_string, second_string)
    fuzz_ratio = fuzz.token_sort_ratio(first_string, second_string)

    if l_distance <= 2:
        score = 50 + 25 * (2 - l_distance)

    elif fuzz_ratio > 80:
        score = fuzz_ratio - 25

    first_len = len(first_string)
    second_len = len(second_string)

    if first_len > second_len / 2 and first_len > 4:
        score += fuzzy_score_string(first_string, second_string)

    return score


def similar_string(first_string, second_string):
    """Determine if two strings are similar.

    Params:
    - first_string: (type: string) first string.
    - second_string: (type: string) second string.

    Returns:
    - result: (type: bool) match result.
    """
    score = score_match(first_string, second_string)

    if score >= SCORE_THRESHOLD_NORMAL:
        return True

    return False


def similar_string_fast(first_string, second_string):
    """Determine if two strings are similar (using two most effective methods).

    Params:
    - first_string: (type: string) first string.
    - second_string: (type: string) second string.

    Returns:
    - result: (type: bool) match result.
    """
    partial_score = fuzz.ratio(first_string, second_string)
    token_score = fuzz.token_set_ratio(first_string, second_string)

    if max(partial_score, token_score) >= SCORE_THRESHOLD_FAST:
        return True

    return False

