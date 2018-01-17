
import logging
import re
import socket
import binascii
import sys
import os
import time
import random
import subprocess
import atexit

import gevent

#create an INET, STREAMing socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#now connect to the web server on port 80
# - the normal http port
s.connect(("www.mcmillan-inc.com", 80))

