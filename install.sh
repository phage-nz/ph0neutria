#!/bin/bash

# ph0neutria install script.
#
# Includes:
# - ph0neutria.
# - Viper.
# - Tor.
#
# https://github.com/phage-nz/ph0neutria

echo 'deb http://deb.torproject.org/torproject.org xenial main' >> /etc/apt/sources.list.d/tor.list
echo 'deb-src http://deb.torproject.org/torproject.org xenial main' >> /etc/apt/sources.list.d/tor.list
gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
apt update && apt upgrade
apt-get -f install autoconf automake bison build-essential clamav clamav-daemon clamav-freshclam flex gcc git libssl-dev libfuzzy-dev libffi-dev libimage-exiftool-perl libjansson-dev libmagic-dev libpcre3 libpcre3-dev libtool make p7zip-full python3-dev python3-pip ssdeep swig tor deb.torproject.org-keyring unrar -y
pip3 install --upgrade setuptools
cd /tmp
git clone https://github.com/VirusTotal/yara
cd yara
./bootstrap.sh
./configure
make
make install
cd /tmp
rm -rf yara
pip3 install yara-python
cd /opt
git clone https://github.com/viper-framework/viper
cd viper
pip3 install -r requirements.txt
# Workaround for requests SSL errors (https://github.com/requests/requests/issues/3006):
pip3 install --force-reinstall requests[security]
cd viper/modules
git clone https://github.com/viper-framework/pdftools
cd /opt
git clone https://github.com/phage-nz/ph0neutria
cd ph0neutria
pip3 install -r requirements.txt
cp core/config/settings.conf.dist core/config/settings.conf
useradd -r -s /bin/false spider
mkdir /home/spider
chown spider:spider /home/spider
chown -R spider:spider /opt/viper
chown -R spider:spider /opt/ph0neutria
usermod -a -G spider clamav
sed -i 's/AllowSupplementaryGroups false/AllowSupplementaryGroups true/g' /etc/clamav/clamd.conf
/etc/init.d/clamav-daemon restart
