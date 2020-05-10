#!/usr/bin/python3

from configparser import SafeConfigParser


import os


class baseObj:
    def __init__(
            self,
            user_agent,
            output_folder,
            geolite_db,
            asn_db,
            date_format,
            redirect_limit,
            use_tor,
            tor_ip,
            tor_port,
            hash_count_limit,
            url_char_limit,
            backend,
            vt_key,
            vt_user,
            vt_req_min,
            vt_score_min,
            vt_preferred_engines,
            malware_days,
            tag_samples,
            blacklisted_tags,
            malware_workers,
            viper_add_url,
            viper_token,
            snake_add_url):
        """Initialise new configuration object.

        Params:
        - user_agent: (type: string) user agent used by Python requests.
        - output_folder: (type: string) temporary folder for downloaded files.
        - geolite_db: (type: string) GeoLite city DB file path.
        - asn_db: (type: string) GeoLite ASN DB file path.
        - date_format: (type: string) format of date stamps sent to Viper.
        - redirect_limit: (type: string) number of HTTP redirects to handle before aborting.
        - use_tor: (type: bool) Use Tor for all malware downloads?
        - tor_ip: (type: string) IP that Tor is listening on.
        - tor_port: (type: string) Port that Tor is listening on.
        - hash_count_limit: (type: int) Number of copies of a unique file to permit.
        - url_char_limit: (type: int) Character limit for acceptable URLs.
        - backend: (type: string) Backend system either Viper or Snake
        - vt_key: (type: string) VirusTotal API key.
        - vt_user: (type: string) VirusTotal username.
        - vt_req_min: (type: string) VirusTotal requests per minute limit.
        - vt_score_min: (type: string) minimum VirusTotal score to accept.
        - vt_preferred_engines: (type: string) comma separated list of preferred VirusTotal engines.
        - malware_days: (type: string) general number of days back to consider malware valid for.
        - malware_workers: (type: int) number of wild file processors to spawn.
        - tag_samples: (type: bool) Tag samples using VirusTotal?
        - blacklisted_tags: (type: string) comma separated list of blacklisted malware family strings.
        - viper_add_url: (type: string) URL of Viper entry addition API.
        - viper_token: (type: string) Django REST API token.
        - snake_add_url: (type: string) URL of snake entry addition API.

        Returns:
        - result: (type: baseObj) configuration object.
        """
        self.user_agent = user_agent
        self.output_folder = output_folder
        self.geolite_db = geolite_db
        self.asn_db = asn_db
        self.date_format = date_format
        self.redirect_limit = int(redirect_limit)
        self.use_tor = use_tor == 'yes'
        self.tor_ip = tor_ip
        self.tor_port = tor_port
        self.hash_count_limit = int(hash_count_limit)
        self.url_char_limit = int(url_char_limit)
        self.backend = backend
        self.vt_key = vt_key
        self.vt_user = vt_user
        self.vt_req_min = int(vt_req_min)
        self.vt_score_min = int(vt_score_min)
        self.vt_preferred_engines = vt_preferred_engines.split(',')
        self.malware_days = int(malware_days)
        self.tag_samples = tag_samples == 'yes'

        if len(blacklisted_tags) > 0:
            self.blacklisted_tags = blacklisted_tags.split(',')

        else:
            self.blacklisted_tags = []

        self.malware_workers = int(malware_workers)
        self.viper_add_url = viper_add_url
        self.viper_token = 'Token {0}'.format(viper_token)

        self.snake_add_url = snake_add_url

def get_base_config(ROOTDIR):
    """Parse config file into a configuration object.

    Returns:
    - result: (type: baseObj) configuration object.

    baseObj:
    - user_agent: (type: string) user agent used by Python requests.
    - output_folder: (type: string) temporary folder for downloaded files.
    - geolite_db: (type: string) GeoLite city DB file path.
    - asn_db: (type: string) GeoLite ASN DB file path.
    - date_format: (type: string) format of date stamps sent to Viper.
    - redirect_limit: (type: int) number of HTTP redirects to handle before aborting.
    - use_tor: (type: string) Use Tor for all malware downloads?
    - tor_ip: (type: string) IP that Tor is listening on.
    - tor_port: (type: string) Port that Tor is listening on.
    - hash_count_limit: (type: int) Number of copies of a unique file to permit.
    - url_char_limit: (type: int) Character limit for acceptable URLs.
    - backend: (type: string) Backend system either Viper or Snake
    - vt_key: (type: string) VirusTotal API key.
    - vt_user: (type: string) VirusTotal username.
    - vt_req_min: (type: int) VirusTotal requests per minute limit.
    - vt_score_min: (type: int) minimum VirusTotal score to accept.
    - vt_preferred_engines: (type: string list) comma separated list of preferred VirusTotal engines.
    - malware_days: (type: int) general number of days back to consider malware valid for.
    - tag_samples: (type: string) Tag samples using VirusTotal?
    - blacklisted_tags: (type: string list) comma separated list of blacklisted malware family strings.
    - malware_workers: (type: int) number of wild file processors to spawn.
    - viper_add_url: (type: string) URL of Viper entry addition API.
    - viper_token: (type: string) Django REST API token.
    - snake_add_url: (type: string) URL of Viper entry addition API.
    """
    parser = SafeConfigParser()
    parser.read(
        os.path.join(
            os.path.dirname(__file__),
            'config',
            'settings.conf'))

    user_agent = parser.get('Core', 'useragent')
    output_folder = parser.get('Core', 'outputfolder')
    geolite_db = parser.get('Core', 'geolitedb')
    asn_db = parser.get('Core', 'asndb')
    date_format = parser.get('Core', 'dateformat')
    redirect_limit = parser.get('Core', 'redirectlimit')
    use_tor = parser.get('Core', 'usetor')
    tor_ip = parser.get('Core', 'torip')
    tor_port = parser.get('Core', 'torport')
    hash_count_limit = parser.get('Core', 'hashcountlimit')
    url_char_limit = parser.get('Core', 'urlcharlimit')
    backend = parser.get('Core', 'backend')
    vt_key = parser.get('VirusTotal', 'apikey')
    vt_user = parser.get('VirusTotal', 'username')
    vt_req_min = parser.get('VirusTotal', 'requestsperminute')
    vt_score_min = parser.get('VirusTotal', 'scoreminimum')
    vt_preferred_engines = parser.get('VirusTotal', 'preferredengines')
    malware_days = parser.get('Malware', 'malwaredays')
    tag_samples = parser.get('Malware', 'tagsamples')
    blacklisted_tags = parser.get('Malware', 'blacklistedtags')
    malware_workers = parser.get('Malware', 'workers')
    viper_add_url = parser.get('Viper', 'addurl')
    viper_token = parser.get('Viper', 'apitoken')
    snake_add_url = parser.get('Snake', 'addurl')

    return baseObj(
        user_agent,
        output_folder,
        geolite_db,
        asn_db,
        date_format,
        redirect_limit,
        use_tor,
        tor_ip,
        tor_port,
        hash_count_limit,
        url_char_limit,
        backend,
        vt_key,
        vt_user,
        vt_req_min,
        vt_score_min,
        vt_preferred_engines,
        malware_days,
        tag_samples,
        blacklisted_tags,
        malware_workers,
        viper_add_url,
        viper_token,
        snake_add_url)
