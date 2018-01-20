#!/usr/bin/env python

import socket
import threading
import sys
from I2PHelper import *
from contextlib import closing

i2p_settings = []

def socket_close(_sock=None):
    if ((_sock != None) and (hasattr(_sock,'close')) and (hasattr(_sock,'shutdown'))):
        _sock.shutdown(socket.SHUT_RDWR)
        _sock.close()

def find_free_port():
    port = 0
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    return port

def test_free_port(port=0):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('', port))
            port = int(s.getsockname()[1])
        return port
    except:
          return 0

def add_socket(port):
    try:
        port = int(port)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
          sock.connect((i2p_settings["server_host"], int(i2p_settings["server_port"])))
          data = (b'ADD_ONION NEW:BEST port=%s\r\n' % port)
          data_len = len(data)  
          i = 0
          sended = 0
          while i < data_len:
            sended = sock.send(data[i:],0)
            if sended == 0:
                break
            i = i + sended
          sock.recv(1024) 
    except:
        return
    return

def del_socket(port):
    try:
        port = int(port)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
          sock.connect((i2p_settings["server_host"], int(i2p_settings["server_port"])))
          data = (b'DEL_ONION %s\r\n' % port)
          data_len = len(data)
          i = 0
          sended = 0
          while i < data_len:
            sended = sock.send(data[i:],0)
            if sended == 0:
                break
            i = i + sended
          sock.recv(1024)
    except:
        return
    return

def i2p_connect(self,addr):
    self.my_connect(addr)
    try:
       addr = self.getsockname()
       self.add_socket_thread = threading.Thread(target=add_socket, args=(addr[1]))
       self.add_socket_thread.start()
    except:
       return

def i2p_close(self):
    try:
       addr = self.getsockname()
       self.del_socket_thread = threading.Thread(target=del_socket, args=(addr[1]))
       self.del_socket_thread.start()
    except:
        ret = False
    self.my_close()

def getnewi2p_bob_socket(outhost='127.0.0.1',outport=3841):
    outn = outhost.endswith(b'.i2p') or outhost.endswith('.i2p')
    outp = outport == b'not_set' or outport == 'not_set'
    if outn:
       old_outhost = outhost
       outhost = b'not_set'
    else:
       old_outhost = outhost
    inport = (b'%s' % find_free_port())
    inport_i = int(inport)
    if (not outp) and (not outn):
       outport_i = int(outport)
       while inport_i == outport_i: 
         inport_i = inport_i + 1    
         inport = (b'%s' % inport_i)
    else:
       outport_i = 0
    insrvid = inport
    outsrvid = inport
    i2p = i2p_bob(i2p_settings["i2p_host"],i2p_settings["i2p_port"],'127.0.0.1',outhost,inport,outport,insrvid,outsrvid,True,True)
    i2p.start()
    i2pxd = i2p.geti2p_bob()
    if outn and outp:
       i2pp = old_outhost
       prf = 0
       subt = prf
    else:
       i2pp = i2pxd["inpkey"]
       prf = int(i2p_settings["port_range_faktor"])
       subt = (int(inport)-prf)
    so = i2p_socket_ex(socket.AF_INET,socket.SOCK_STREAM,0,None,i2pp,prf)
    setattr(so,'my_connect',getattr(so,'connect'))
    setattr(so,'my_close',getattr(so,'close'))
    setattr(so,'connect',i2p_connect)
    setattr(so,'close',i2p_close)
    so.connect(('127.0.0.1',subt))
    so.send(b'',0)
    return so

def handle(buffer):
    return buffer

def transfer(src, dst):#, i2p_dst=None):
    #if i2p_dst != None:
    #    dst = i2p_dst
    src_name = src.getsockname()
    src_address = src_name[0]
    src_port = src_name[1]
    dst_name = dst.getsockname()
    dst_address = dst_name[0]
    dst_port = dst_name[1]
    print "[+] Starting transfer [%s:%d] => [%s:%d]" % (src_name, src_port, dst_name, dst_port)
    while True:
        buffer = src.recv(0x1000)
        if not buffer:
            print "[-] No data received! Breaking..."
            break
        # print "[+] %s:%d => %s:%d [%s]" % (src_address, src_port, dst_address, dst_port, repr(buffer))
        print "[+] %s:%d => %s:%d => Length : [%d]" % (src_address, src_port, dst_address, dst_port, len(buffer))
        dst.send(handle(buffer))
    print "[+] Closing connecions! [%s:%d]" % (src_address, src_port)
    src.close()
    print "[+] Closing connecions! [%s:%d]" % (dst_address, dst_port)
    dst.close()


SOCKS_VERSION = 5

ERROR_VERSION = "[-] Client version error!"
ERROR_METHOD = "[-] Client method error!"

# ALLOWED_METHOD = [0, 2]
ALLOWED_METHOD = [0]

def socks_selection(socket):
    client_version = ord(socket.recv(1))
    print "[+] client version : %d" % (client_version)
    if not client_version == SOCKS_VERSION:
        socket.shutdown(socket.SHUT_RDWR)
        socket.close()
        return (False, ERROR_VERSION)
    support_method_number = ord(socket.recv(1))
    print "[+] Client Supported method number : %d" % (support_method_number)
    support_methods = []
    for i in range(support_method_number):
        method = ord(socket.recv(1))
        print "[+] Client Method : %d" % (method)
        support_methods.append(method)
    selected_method = None
    for method in ALLOWED_METHOD:
        if method in support_methods:
            selected_method = 0
    if selected_method == None:
        socket.shutdown(socket.SHUT_RDWR)
        socket.close()
        return (False, ERROR_METHOD)
    print "[+] Server select method : %d" % (selected_method)
    response = chr(SOCKS_VERSION) + chr(selected_method)
    socket.send(response)
    return (True, socket)

CONNECT = 1
BIND = 2
UDP_ASSOCIATE = 3

IPV4 = 1
DOMAINNAME = 3
IPV6 = 4

CONNECT_SUCCESS = 0

ERROR_ATYPE = "[-] Client address error!"

RSV = 0
BNDADDR = "\x00" * 4
BNDPORT = "\x00" * 2

def socks_request(local_socket):
    client_version = ord(local_socket.recv(1))
    print "[+] client version : %d" % (client_version)
    if not client_version == SOCKS_VERSION:
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_VERSION)
    cmd = ord(local_socket.recv(1))
    if cmd == CONNECT:
        print "[+] CONNECT request from client"
        rsv  = ord(local_socket.recv(1))
        if rsv != 0:
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, ERROR_RSV)
        atype = ord(local_socket.recv(1))
        if atype == IPV4:
            dst_address = ("".join(["%d." % (ord(i)) for i in local_socket.recv(4)]))[0:-1]
            print "[+] IPv4 : %s" % (dst_address)
            dst_port = ord(local_socket.recv(1)) * 0x100 + ord(local_socket.recv(1))
            print "[+] Port : %s" % (dst_port)
            #remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #rs = getnewi2p_bob_socket(dst_address,dst_port)
            try:
                print "[+] Connecting : %s:%s" % (dst_address, dst_port)
                #remote_socket.connect((dst_address, dst_port))
                remote_socket = getnewi2p_bob_socket(dst_address,dst_port)
                response = ""
                response += chr(SOCKS_VERSION)
                response += chr(CONNECT_SUCCESS)
                response += chr(RSV)
                response += chr(IPV4)
                response += BNDADDR
                response += BNDPORT
                local_socket.send(response)
                print "[+] Tunnel connected! Tranfering data..."
                r = threading.Thread(target=transfer, args=(
                    local_socket, remote_socket))#, rs))
                r.start()
                s = threading.Thread(target=transfer, args=(
                    remote_socket, local_socket))#, rs))
                s.start()
                f = threading.Thread(target=add_socket, args=(
                    dst_port))
                f.start()
                return (True, (local_socket, remote_socket))#, rs))
            except socket.error as e:
                print e
                remote_socket.shutdown(socket.SHUT_RDWR)
                remote_socket.close()
                local_socket.shutdown(socket.SHUT_RDWR)
                local_socket.close()
                #if rs != None:
                #   rs.shutdown(socket.SHUT_RDWR)
                #   rs.close()

        elif atype == DOMAINNAME:
            domainname_length = ord(local_socket.recv(1))
            domainname = ""
            for i in range(domainname_length):
                domainname += (local_socket.recv(1))
            print "[+] Domain name : %s" % (domainname)
            dst_port = ord(local_socket.recv(1)) * 0x100 + ord(local_socket.recv(1))
            print "[+] Port : %s" % (dst_port)
            #remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #rs = getnewi2p_bob_socket(domainname,dst_port)  
            try:
                print "[+] Connecting : %s:%s" % (domainname, dst_port)
                #remote_socket.connect((domainname, dst_port))
                remote_socket = getnewi2p_bob_socket(domainname,dst_port) 
                response = ""
                response += chr(SOCKS_VERSION)
                response += chr(CONNECT_SUCCESS)
                response += chr(RSV)
                response += chr(IPV4)
                response += BNDADDR
                response += BNDPORT
                local_socket.send(response)
                print "[+] Tunnel connected! Tranfering data..."
                r = threading.Thread(target=transfer, args=(
                    local_socket, remote_socket))#, rs))
                r.start()
                s = threading.Thread(target=transfer, args=(
                    remote_socket, local_socket))#, rs))
                s.start()
                f = threading.Thread(target=add_socket, args=(
                    dst_port))
                f.start()
                return (True, (local_socket, remote_socket))#, rs))
            except socket.error as e:
                print e
                remote_socket.shutdown(socket.SHUT_RDWR)
                remote_socket.close()
                local_socket.shutdown(socket.SHUT_RDWR)
                local_socket.close()
                #if rs != None:
                #   rs.shutdown(socket.SHUT_RDWR)
                #   rs.close()
        elif atype == IPV6:
            dst_address = int(local_socket.recv(4).encode("hex"), 16)
            print "[+] IPv6 : %x" % (dst_address)
            dst_port = ord(local_socket.recv(1)) * 0x100 + ord(local_socket.recv(1))
            print "[+] Port : %s" % (dst_port)
            #remote_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            #rs = getnewi2p_bob_socket(dst_address,dst_port)
            #remote_socket.connect((dst_address, dst_port))
            remote_socket = getnewi2p_bob_socket(dst_address,dst_port)
            remote_socket.shutdown(socket.SHUT_RDWR)
            remote_socket.close()
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            #if rs != None:
            #       rs.shutdown(socket.SHUT_RDWR)
            #       rs.close()
            return (False, ERROR_ATYPE)
        else:
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, ERROR_ATYPE)
    elif cmd == BIND:
        # TODO
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_CMD)
    elif cmd == UDP_ASSOCIATE:
        # TODO
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_CMD)
    else:
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_CMD)
    return (True, local_socket)

def server(local_host, local_port, max_connection):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((local_host, local_port))
        server_socket.listen(max_connection)
        print '[+] Server started [%s:%d]' % (local_host, local_port)
        while True:
            local_socket, local_address = server_socket.accept()
            print '[+] Detect connection from [%s:%s]' % (local_address[0], local_address[1])
            result = socks_selection(local_socket)
            if not result[0]:
                print "[-] socks selection error!"
                break
            result = socks_request(result[1])
            if not result[0]:
                print "[-] socks request error!"
                break
            # local_socket, remote_socket = result[1]
            # TODO : loop all socket to close...
        print "[+] Releasing resources..."
        local_socket.close()
        print "[+] Closing server..."
        server_socket.close()
        print "[+] Server shuted down!"
    except  KeyboardInterrupt:
        print ' Ctl-C stop server'
        try:
            remote_socket.close()
        except:
            pass
        try:
            local_socket.close()
        except:
            pass
        try:
            server_socket.close()
        except:
            pass
        #try:
        #    rs.close()
        #except:
        #    pass
        return

def startMain(host=None,port=None):
    if host == None or port == None:
       return 0
    LOCAL_HOST = host
    LOCAL_PORT = int(port)
    MAX_CONNECTION = 0x10
    server(LOCAL_HOST, LOCAL_PORT, MAX_CONNECTION)


def main():
    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython %s [L_HOST] [L_PORT]" % (sys.argv[0])
        print "Example : "
        print "\tpython %s 127.0.0.1 1080" % (sys.argv[0])
        print "Author : "
        print "\tWangYihang <wangyihanger@gmail.com>"
        exit(1)
    LOCAL_HOST = sys.argv[1]
    LOCAL_PORT = int(sys.argv[2])
    #REMOTE_HOST = sys.argv[3]
    #REMOTE_PORT = int(sys.argv[4])
    MAX_CONNECTION = 0x10
    server(LOCAL_HOST, LOCAL_PORT, MAX_CONNECTION)


if __name__ == "__main__":
    i2p_settings = load_settings()
    le = len(sys.argv)
    args=[0,1,2]
    if le > 0:
       args[0] = sys.argv[0]
    else:
       args[0] = 'I2PSocksServer.py'

    if le > 1:
       args[1] = sys.argv[1]
    else:
       args[1] = '127.0.0.1'

    if le > 2:
       args[2] = sys.argv[2]
    else:
       args[2] = '1080'
    
    sys.argv = args
    main()
