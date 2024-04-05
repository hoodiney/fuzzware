export PS1='\e[92m\u\e[0m@\e[94m\h\e[0m:\e[35m\w\e[0m# '
sudo apt install python3-dbg file
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
UNICORN_DEBUG=yes ./install_local_dbg.sh