       .__    _______                        __         .__       
______ |  |__ \   _  \   ____   ____  __ ___/  |________|__|____  
\____ \|  |  \/  /_\  \ /    \_/ __ \|  |  \   __\_  __ \  \__  \ 
|  |_> >   Y  \  \_/   \   |  \  ___/|  |  /|  |  |  | \/  |/ __ \_
|   __/|___|  /\_____  /___|  /\___  >____/ |__|  |__|  |__(____  /
|__|        \/       \/     \/     \/                           \/

                  ph0neutria malware crawler
                            v0.1
             https://github.com/t0x0-nz/ph0neutria

About
"""""
ph0neutria is a malware zoo builder that sources samples from MalShare and the wild (via the Malc0de database). All fetched samples are stored in Viper for ease of access.

This project was inspired by Ragpicker (https://github.com/robbyFux/Ragpicker, formerly known as "Malware Crawler"). However, ph0neutria aims to:
- Limit the scope of crawling to only frequently updated and reliable sources.
- Offer a single, reliable and robust storage mechanism.
- Minimise work that can be done by Viper.

What does the name mean? "Phoneutria nigriventer" is commonly known as the Brazillian Wandering Spider: https://en.wikipedia.org/wiki/Brazilian_wandering_spider


Installation and Usage
""""""""""""""""""""""
# It's highly advised that you use an anonymous VPN service to collect wild samples with. I'd also recommend collecting them on a machine that you use only for the purpose of piecing together your malware zoo.

# Update box:
apt-get update
apt-get ugprade -y

# Install prereq's:
apt-get -f install git libssl-dev swig libfuzzy-dev libffi-dev python-pip -y
pip install --upgrade pip
pip install BeautifulSoup SQLAlchemy PrettyTable python-magic
cd ~
wget http://heanet.dl.sourceforge.net/project/ssdeep/ssdeep-2.13/ssdeep-2.13.tar.gz
tar -xzvf ssdeep-2.13.tar.gz
cd ssdeep-2.13
./configure && make
sudo make install
sudo pip install pydeep
cd ..
rm -rf ssdeep-2.13

# Install Viper:
cd /opt
git clone https://github.com/viper-framework/viper
cd viper
pip install -r requirements.txt
make install

# Fetch ph0neutria:
cd ~
git clone https://github.com/t0x0-nz/ph0neutria

# Start the Viper API:
cd /opt/viper
python viper-api

# Start the Viper web interface:
cd /opt/viper
python viper-web

# Complete the config file at: ~/ph0neutria/settings.conf

# Start ph0neutria:
cd ~/ph0neutria
python run.py

# You can press Ctrl+C at any time to kill the run. You are free to run it again as soon as you'd like - you can't end up with database duplicates. Just be mindful of your daily MalShare request limit.
