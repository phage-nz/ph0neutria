#!/usr/bin/python
from datetime import datetime


class MalwareHost(object):
    def __init__(self, address, sha256, source):
        """Initialise a new malware host.

        Params:
        - address: (type: string) IP address.
        - sha256: (type: string) SHA256 hash of payload.
        - source: (type: string) reporting source.

        Returns:
        - result: (type: MalwareHost) malware host object.
        """
        self.address = address
        self.sha256 = sha256
        self.source = source


class MalwareUrl(object):
    def __init__(self, host, address, url, source):
        """Initialise a new malware URL.

        Params:
        - host: (type: string) site domain/address.
        - address: (type: string) IP address.
        - url: (type: string) URL of site.
        - source: (type: string) reporting source.

        Returns:
        - result: (type: MalwareUrl) malware URL object.
        """
        self.host = host
        self.address = address
        self.url = url
        self.source = source
