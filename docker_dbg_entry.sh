#!/bin/bash
echo "deb http://ubuntu.ethz.ch/ubuntu/ focal main restricted" | sudo tee /etc/apt/sources.list
echo "deb http://ubuntu.ethz.ch/ubuntu/ focal-updates main restricted" | sudo tee -a /etc/apt/sources.list
echo "deb http://ubuntu.ethz.ch/ubuntu/ focal universe" | sudo tee -a /etc/apt/sources.list
echo "deb http://ubuntu.ethz.ch/ubuntu/ focal-updates universe" | sudo tee -a /etc/apt/sources.list
cd /home/user/fuzzware_repo || exit
sudo apt update
# sudo apt install -y python3-dbg file
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
# UNICORN_DEBUG=yes ./install_local.sh
./install_local.sh
echo "source /home/user/.virtualenvs/fuzzware/bin/activate" | sudo tee -a /home/user/.bashrc
source /home/user/.bashrc
/bin/bash