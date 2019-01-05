#!/usr/bin/python3

from .dns_utils import resolve_dns
from .config_utils import get_base_config
from .log_utils import get_module_logger


import codecs
import geoip2.database
import netaddr
import os
import random
import re
import time
import validators


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


def resolve_country(host_name):
    """Resolve an IP address or domain to it's hosting country.

    Params:
    - host_name: (type: string) FQDN or IP address.

    Returns:
    - result: (type: string) two-letter country code.
    """
    isCidr = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', host_name)

    if isCidr:
        host_name = str(random.choice(netaddr.IPNetwork(host_name)))

    if validators.ipv4(host_name):
        return geo_lookup(host_name)

    ip_addr = resolve_dns(host_name)

    if ip_addr:
        return geo_lookup(ip_addr)

    return 'ZZ'


def geo_lookup(ip_addr):
    """Resolve an IP address to it's hosting country.

    Params:
    - ip_addr: (type: string) IP address.

    Returns:
    - result: (type: string) two-letter country code.
    """
    if validators.ipv4(ip_addr):
        try:
            if ip_addr == '255.255.255.255':
                return 'ZZ'

            with geoip2.database.Reader(BASECONFIG.geolite_db) as reader:
                response = reader.city(ip_addr)

                if response is not None:
                    if response.country.iso_code is not None:
                        return response.country.iso_code

                    if response.continent.code is not None:
                        return response.continent.code

        except Exception as e:
            LOGGING.warning(
                'Failed to perform GeoLookup for address {0}: {1}'.format(
                    ip_addr, str(e)))

    else:
        LOGGING.warning('Invalid IP address: {0}'.format(ip_addr))

    return 'ZZ'


def resolve_asn(ip_addr):
    """Resolve the ASN of an IP address or FQDN.

    Params:
    - ip_addr: (type: string) FQDN or IP address.

    Returns:
    - result: (type: string) ASN number and organisation.
    """
    isCidr = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', ip_addr)

    if isCidr:
        ip_addr = str(random.choice(netaddr.IPNetwork(ip_addr)))

    if validators.ipv4(ip_addr):
        return asn_lookup(ip_addr)

    host_addr = resolve_dns(ip_addr)

    if host_addr:
        return asn_lookup(host_addr)

    return 'AS0000 Unknown'


def asn_lookup(ip_addr):
    """Resolve the ASN of an IP address.

    Params:
    - ip_addr: (type: string) IP address.

    Returns:
    - result: (type: string) ASN number and organisation.
    """
    if validators.ipv4(ip_addr):
        try:
            if ip_addr == '255.255.255.255':
                return 'AS0000 Unknown'

            with geoip2.database.Reader(BASECONFIG.asn_db) as reader:
                response = reader.asn(ip_addr)

                if response is not None:
                    asn_number = response.autonomous_system_number
                    asn_org = response.autonomous_system_organization
                    return 'AS{0} {1}'.format(asn_number, asn_org)

        except Exception as e:
            LOGGING.warning(
                'Failed to perform ASN lookup for address {0}: {1}'.format(
                    ip_addr, str(e)))

    else:
        LOGGING.warning('Invalid IP address: {0}'.format(ip_addr))

    return 'AS0000 Unknown'