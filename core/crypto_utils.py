#!/usr/bin/python3

from .config_utils import get_base_config
from .log_utils import get_module_logger


import hashlib
import os
import random
import string
import sys


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


def hash_file(file_name):
    """Produce a SHA256 hash of a file.

    Params:
    - file_name: (type: string) path of file to hash.

    Returns:
    - file_sum: (type: string) hex encoded SHA256 digest of file.
    """
    with open(file_name, 'rb') as file_to_hash:
        data = file_to_hash.read()
        file_sum = hashlib.sha256(data).hexdigest()

    return file_sum


def random_string(length):
    """Produce a random alphanumeric string of specific length.

    Params:
    - length: (type: int) length of output string.

    Returns:
    - result: (type: string) random string.
    """
    return ''.join(
        random.choice(
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits) for i in range(length))
