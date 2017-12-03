#!/bin/bash

# ph0neutria install script.
#
# Includes:
# - ph0neutria malware crawler.
# - Tor.
# - Viper.
#
# https://github.com/phage-nz/ph0neutria

echo 'deb http://deb.torproject.org/torproject.org xenial main' >> /etc/apt/sources.list.d/tor.list
echo 'deb-src http://deb.torproject.org/torproject.org xenial main' >> /etc/apt/sources.list.d/tor.list
gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
apt update && apt upgrade
apt-get -f install autoconf bison build-essential clamav clamav-daemon clamav-freshclam flex gcc git libssl-dev libfuzzy-dev libffi-dev libimage-exiftool-perl libjansson-dev libmagic-dev libpcre3-dev libtool pcre python-dev python-lxml python-pip swig tor deb.torproject.org-keyring -y
pip install --upgrade pip
pip install BeautifulSoup coloredlogs numpy OTXv2 pandas pefile pyclamd PySocks python-Levenshtein python-magic requests requests_toolbelt scipy sklearn validators
cd /tmp
wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
tar -zxvf ssdeep-2.14.1.tar.gz
cd ssdeep-2.14.1
./configure && make
make install
pip install pydeep
cd /tmp
rm -rf ssdeep-2.14.1
git clone https://github.com/smarnach/pyexiftool
cd pyexiftool
python setup.py install
cd /tmp
rm -rf pyexiftool
git clone https://github.com/plusvic/yara
cd yara
./bootstrap.sh
autoreconf -vi --force
./configure --enable-cuckoo --enable-magic
make
make install
cd yara-python/
python setup.py install
cd /tmp
rm -rf yara
cd /opt
git clone https://github.com/viper-framework/viper
cd viper
pip install -r requirements.txt
# Workaround for requests SSL errors (https://github.com/requests/requests/issues/3006):
pip install --force-reinstall requests[security]
cd viper/modules
git clone https://github.com/viper-framework/pdftools
cd /opt
git clone https://github.com/phage-nz/ph0neutria
useradd -r -s /bin/false spider
mkdir /home/spider
chown spider:spider /home/spider
chown -R spider:spider /opt/viper
chown -R spider:spider /opt/ph0neutria
usermod -a -G spider clamav
sed -i 's/AllowSupplementaryGroups false/AllowSupplementaryGroups true/g' /etc/clamav/clamd.conf
/etc/init.d/clamav-daemon restart
