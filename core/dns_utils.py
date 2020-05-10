#!/usr/bin/python3

from .config_utils import get_base_config
from .log_utils import get_module_logger


import DNS
import os
import sys
import time
import validators


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


DNS.defaults['server'] = ['8.8.8.8', '8.8.4.4']
DNS.defaults['timeout'] = 5


def forward_dns_lookup(host_name):
    """Perform a DNS lookup of a FQDN.

    Params:
    - host_name: (type: string) FQDN to perform lookup of.

    Returns:
    - result: (type: string) resulting IP address.
    """
    try:
        ip_list = DNS.dnslookup(host_name, 'A')

        if len(ip_list) > 0:
            for ip_addr in ip_list:
                if validators.ipv4(ip_addr):
                    return ip_addr

    except BaseException:
        LOGGING.warning('DNS lookup of {0} failed.'.format(host_name))
        return None

    return None


def resolve_dns(host_name):
    """Perform a DNS lookup of a FQDN.

    Params:
    - host_name: (type: string) FQDN to perform lookup of.

    Returns:
    - result: (type: string) resulting IP address.
    """
    if validators.ipv4(host_name):
        return host_name

    ip_addr = forward_dns_lookup(host_name)

    if ip_addr is not None:
        return ip_addr

    return False
