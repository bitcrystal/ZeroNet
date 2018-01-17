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

import signal
import gevent
from I2P import I2PHelper
from I2P import I2PSocksServer
from I2P import IntThread
from IntThread import *
from I2PHelper import *
from Config import config
from Crypt import CryptRsa
from Site import SiteManager
from lib.PySocks import socks
try:
    from gevent.coros import RLock
except:
    from gevent.lock import RLock
from util import helper
from Debug import Debug
from Plugin import PluginManager


@PluginManager.acceptPlugins
class I2PManager(object):
    def __init__(self, fileserver_ip=None, fileserver_port=None):
        self.privatekeys = {}  # I2P: Privatekey
        self.privatekeys_ret = {}
        self.site_onions = {}  # Site address: I2P
        self.log = logging.getLogger("I2PManager")
        self.start_onions = None
        self.conn = None
        self.lock = RLock()
        if config.i2p == "disable":
            self.enabled = False
            self.start_onions = False
            self.setStatus("Disabled")
        else:
            self.enabled = True
            self.setStatus("Waiting")

        if fileserver_port:
            self.fileserver_port = fileserver_port
        else:
            self.fileserver_port = config.fileserver_port
       
        self.ip, self.port = config.i2p_controller.split(":")
        self.cookiefile_path = config.i2p_cookiefile_path
        self.port = int(self.port)
        self.ip_bob, self.port_bob = config.i2p_bob_server.split(":")
        self.port_bob = int(self.port_bob)
        self.i2p_debug = config.i2p_debug
        self.i2p_hs_limit = int(config.i2p_hs_limit)
        self.i2p_start = config.i2p_start
        self.port_range_faktor = int(config.i2p_port_range_faktor)
        self.port_range_faktor_endless = self.i2p_hs_limit + self.port_range_faktor
        self.port_range_faktor_count = 1
        
        
        self.http_proxy_ip, self.http_proxy_port = config.i2p_http_proxy.split(":")
        self.http_proxy_port = int(self.http_proxy_port)

        self.socks_proxy_ip, self.socks_proxy_port = config.i2p_socks_proxy.split(":")
        self.socks_proxy_port = int(self.socks_proxy_port)

        self.i2p_proxy = None
        self.i2p_helper = None
        self.i2p_proxy_started = False        
        self.i2p_helper_started = False       
 
        if self.i2p_start:
           self.init_bob() 

        # Test proxy port
        if config.i2p != "disable":
            if self.i2p_start:
               self.start_I2P()
            try:
                assert self.connect(), "No connection"
                self.log.debug("I2P proxy port %s check ok" % config.i2p_controller)
            except Exception, err:
                self.log.info("Starting self-bundled I2P, due to I2P proxy port %s check error: %s" % (config.i2p_controller, err))
                self.enabled = False
                # Change to self-bundled Tor ports
                from lib.PySocks import socks
                self.port = 1234
                self.socks_proxy_port = 1235
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", self.socks_proxy_port)

    def setStatus(self, status):
        self.status = status 
        if "ui_server" in dir(sys.modules["main"]):
            sys.modules["main"].ui_server.updateWebsocket()

    def startTor(self):
        return False

    def init_bob(self):
        create_settings()
        ret = {}
        ret = load_settings()
        ret["server_port"] = self.port    
        ret["server_host"] = self.ip
        ret["i2p_host"] = self.ip_bob
        ret["i2p_port"] = self.port_bob
        ret["cookiefile_path"] = self.cookiefile_path
        ret["debug"] = self.i2p_debug
        ret["port_range_faktor"] = self.port_range_faktor
        ret["i2p_http_proxy_host"] = self.http_proxy_ip
        ret["i2p_http_proxy_port"] = self.http_proxy_port
        save_settings(ret)

    def start_I2P(self):
        self.startI2P()
        time.sleep(3)
        self.startI2PProxy()
        time.sleep(10)
   
    def stop_I2P(self):
        self.stopI2P()
        time.sleep(3)
        self.stopI2PProxy()

    def startI2P(self):
        if self.i2p_helper_started:
           return False

        self.i2p_helper = IntThread(startI2PHelperMain,(True,True),True)
        self.i2p_helper.start()
        self.i2p_helper_started = True
        return True
  

    def stopI2P(self):
        if not self.i2p_helper_started:
           return False

        self.i2p_helper.stop()
        self.i2p_helper_started = False
        return True


    def startI2PProxy(self):
        if self.i2p_proxy_started:
           return False
           
        self.i2p_proxy = IntThread(I2PSocksServer.startMain,(self.socks_proxy_ip,self.socks_proxy_port),True)
        self.i2p_proxy.start()
        self.i2p_proxy_started = True
        return True
               

    def stopI2PProxy(self):
        if not self.i2p_proxy_started:
           return False

        self.i2p_proxy.stop()  
        self.i2p_proxy_started = False
        return True


    def stopTor(self):
       return False

    def downloadTor(self):
        return False

    def connect(self):
        if not self.enabled:
            return False
        self.site_onions = {}
        self.privatekeys = {}

        return self.connectController()

    def connectController(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.log.info("Connecting to I2P Controller %s:%s" % (self.ip, self.port))
        try:
            with self.lock:
                print self.ip
                print self.port
                print 'dddd'
                conn.connect((self.ip, self.port))

                # Auth cookie file
                res_protocol = self.send("PROTOCOLINFO", conn)
                cookie_match = re.search('COOKIEFILE="(.*?)"', res_protocol)
                print res_protocol
                print cookie_match
                assert cookie_match
                cookie_file = cookie_match.group(1).decode("string-escape")
                auth_hex = binascii.b2a_hex(open(cookie_file, "rb").read())
                print auth_hex
                res_auth = self.send("AUTHENTICATE %s" % auth_hex, conn)
                print res_auth
                assert "250 OK" in res_auth, "Authenticate error %s" % res_auth
                
                # Version 0.2.7.5 required because ADD_ONION support
                res_version = self.send("GETINFO version", conn)
                version = re.search('version=([0-9\.]+)', res_version).group(1)
                assert float(version.replace(".", "0", 2)) >= 200.0, "Tor version >=0.2.7.5 required, found: %s" % version

                self.setStatus(u"Connected (%s)" % res_auth)
                self.conn = conn
        except Exception, err:
             print 'ddddfdffsd'
             self.conn = None
             self.setStatus(u"Error (%s)" % err)
             self.log.error("I2P controller connect error: %s" % Debug.formatException(err))
             self.enabled = False
        return self.conn

    def disconnect(self):
        self.conn.close()
        self.conn = None

    def startOnions(self):
        if self.enabled:
            self.log.debug("Start i2ps")
            self.start_onions = True

    # Get new exit node ip
    def resetCircuits(self):
        res = self.request("SIGNAL NEWNYM")
        if "250 OK" not in res:
            self.setStatus(u"Reset circuits error (%s)" % res)
            self.log.error("I2P reset circuits error: %s" % res)

    def addOnion(self):
        if len(self.privatekeys) >= config.i2p_hs_limit:
            return random.choice(self.privatekeys.keys())

        result = self.makeOnionAndKey()
        if result:
            onion_address, onion_privatekey = result
            self.privatekeys[onion_address] = onion_privatekey
            self.setStatus(u"OK (%s i2ps running)" % len(self.privatekeys))
            SiteManager.peer_blacklist.append((onion_address + ".i2p", self.fileserver_port))
            return onion_address
        else:
            return False

    def makeOnionAndKey(self):
        res = self.request("ADD_ONION NEW:RSA1024 port=%s" % self.fileserver_port)
        match = re.search("ServiceID=([A-Za-z0-9]+).*PrivateKey=RSA1024:(.*?)[\r\n]", res, re.DOTALL)
        if match:
            onion_address, onion_privatekey = match.groups()
            return (onion_address, onion_privatekey)
        else:
            self.setStatus(u"AddI2P error (%s)" % res)
            self.log.error("I2P addOnion error: %s" % res)
            return False


    def delOnion(self, address):
        res = self.request("DEL_ONION %s" % address)
        if "250 OK" in res:
            del self.privatekeys[address]
            self.setStatus("OK (%s i2ps running)" % len(self.privatekeys))
            return True
        else:
            self.setStatus(u"DelI2P error (%s)" % res)
            self.log.error("I2P delI2P error: %s" % res)
            self.disconnect()
            return False

    def request(self, cmd):
        with self.lock:
            if not self.enabled:
                return False
            if not self.conn:
                if not self.connect():
                    return ""
            return self.send(cmd)

    def send(self, cmd, conn=None):
        if not conn:
            conn = self.conn
        self.log.debug("> %s" % cmd)
        back = ""
        for retry in range(2):
            try:
                conn.sendall("%s\r\n" % cmd)
                while not back.endswith("250 OK\r\n"):
                    back += conn.recv(1024 * 64).decode("utf8", "ignore")
                break
            except Exception, err:
                self.log.error("I2P send error: %s, reconnecting..." % err)
                self.disconnect()
                time.sleep(1)
                self.connect()
                back = None
        self.log.debug("< %s" % back.strip())
        return back

    def getPrivatekey(self, address):
        return self.privatekeys[address]

    def getPublickey(self, address):
        return self.privatekeys[address]

    def getOnion(self, site_address):
        with self.lock:
            if not self.enabled:
                return None
            if self.start_onions:  # Different onion for every site
                onion = self.site_onions.get(site_address)
            else:  # Same onion for every site
                onion = self.site_onions.get("global")
                site_address = "global"
            if not onion:
                self.site_onions[site_address] = self.addOnion()
                onion = self.site_onions[site_address]
                self.log.debug("Created new I2P hidden service for %s: %s" % (site_address, onion))
            return onion

    # Creates and returns a
    # socket that has connected to the I2P Network
    def createSocket(self, onion, port):
        if not self.enabled:
            return False
        self.log.debug("Creating new I2P socket to %s:%s" % (onion, port))

        if config.i2p == "always":  # Every socket is proxied by default, in this mode
           sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
           sock = socks.socksocket()
           sock.set_proxy(socks.SOCKS5, self.proxy_ip, self.proxy_port)
        
        return sock


if __name__ == "__main__":
    e = I2PManager()
    onion = ''
    port = 44444
    ol = i2p_socket_ex(socket.AF_INET,socket.SOCK_STREAM,0,None,'l')
    ol.connect(('127.0.0.1',2817))
    ol.send(b'ist\n')
    ol.settimeout(10.0)
    date = ol.recv(4096)
    date2 = ol.recv(4096)
    ol.settimeout(None)
    print(date)
    print(date2)
    ol.close()
