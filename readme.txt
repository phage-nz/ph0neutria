       .__    _______                        __         .__       
______ |  |__ \   _  \   ____   ____  __ ___/  |________|__|____  
\____ \|  |  \/  /_\  \ /    \_/ __ \|  |  \   __\_  __ \  \__  \ 
|  |_> >   Y  \  \_/   \   |  \  ___/|  |  /|  |  |  | \/  |/ __ \_
|   __/|___|  /\_____  /___|  /\___  >____/ |__|  |__|  |__(____  /
|__|        \/       \/     \/     \/                           \/

                  ph0neutria malware crawler
                            v0.4.1
             https://github.com/t0x0-nz/ph0neutria

About
"""""
ph0neutria is a malware zoo builder that sources samples from MalShare and the wild (via the Malc0de and VX Vault databases). All fetched samples are stored in Viper for ease of access.

This project was inspired by Ragpicker (https://github.com/robbyFux/Ragpicker, formerly known as "Malware Crawler"). However, ph0neutria aims to:
- Limit the scope of crawling to only frequently updated and reliable sources.
- Offer a single, reliable and well organised storage mechanism.
- Not do work that can instead be done by Viper.

What does the name mean? "Phoneutria nigriventer" is commonly known as the Brazillian Wandering Spider: https://en.wikipedia.org/wiki/Brazilian_wandering_spider


Screenshots
"""""""""""
CLI: http://iforce.co.nz/i/yoxgsguf.cof.png
Web: http://iforce.co.nz/i/dws1yb4z.zx4.png


Installation
""""""""""""
# Update box:
apt-get update
apt-get ugprade -y

# Install prereq's:
apt-get -f install autoconf git libssl-dev swig libfuzzy-dev libffi-dev libjansson-dev libmagic-dev libtool python-pip -y
pip install --upgrade pip
pip install BeautifulSoup coloredlogs SQLAlchemy PrettyTable python-magic requests_toolbelt validators
cd ~
wget http://heanet.dl.sourceforge.net/project/ssdeep/ssdeep-2.13/ssdeep-2.13.tar.gz
tar -xzvf ssdeep-2.13.tar.gz
cd ssdeep-2.13
./configure && make
sudo make install
sudo pip install pydeep
cd ..
rm -rf ssdeep-2.13
git clone https://github.com/plusvic/yara
cd yara
./bootstrap.sh
autoreconf -vi --force
./configure --enable-cuckoo --enable-magic
make
make install
cd yara-python/
python setup.py install
cd ../..
rm -rf yara
pip install yara-python

# Install Viper:
cd /opt
git clone https://github.com/viper-framework/viper
cd viper
pip install -r requirements.txt
make install

# Clone ph0neutria:
cd /opt
git clone https://github.com/t0x0-nz/ph0neutria

# Create user:
useradd -r -s /bin/false spider
mkdir /home/spider
chown spider:spider /home/spider
chown -R spider:spider /opt/viper
chown -R spider:spider /opt/ph0neutria


Usage
"""""
It's highly advised that you use an anonymous VPN service to collect wild samples with. I'd also recommend collecting them on a machine that you use only for the purpose of piecing together your malware zoo.

Start the Viper API:
cd /opt/viper
sudo -H -u spider python viper-api

Start the Viper web interface:
cd /opt/viper
sudo -H -u spider python viper-web

Complete the config file at: /opt/ph0neutria/settings.conf

Start ph0neutria:
cd /opt/ph0neutria
sudo -H -u spider python run.py

You can press Ctrl+C at any time to kill the run. You are free to run it again as soon as you'd like - you can't end up with database duplicates. Just be mindful of your daily MalShare request limit. If you run over the limit, set 'disable=yes' in the [MalShare] section of the config file. To help reduce the chance of exceeding your limit you can also set 'remotefirst=yes' in the same section - which will first attempt to download the file from it's original host before pulling it from MalShare.

To run this daily, create a script in /etc/cron.daily with the following:

#!/bin/bash
cd /opt/ph0neutria && sudo -H -u spider python run.py


Tags
""""
{1},{2},{3},{4},{5},{6}

1) File MD5.
2) Source domain (see Known Issues).
3) Source URL (see Known Issues).
4) URL MD5 (for Wild files only - used for validation).
5) Date stamp.
6) Source agent (Wild or MalShare).

The original name of the file forms the identifying name within Viper.


Known Issues
""""""""""""
- Viper tags are forced to lowercase (by Viper). If you do not want this behavior then I'd recommend removing all occurrences of .lower() in viper/viper/core/database.py


References and Credits
""""""""""""""""""""""
http://malshare.com/doc.php - MalShare API documentation.
http://viper-framework.readthedocs.io/en/latest/usage/web.html - Viper API documentation.
http://malshare.com/ - Thanks for the samples.
http://malc0de.com/ - Thanks for the samples.
http://vxvault.net/ - Thanks for the samples.
https://github.com/robbyFux/Ragpicker - Thanks for the inspiration.
