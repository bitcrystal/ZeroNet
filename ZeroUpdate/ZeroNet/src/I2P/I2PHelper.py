import os.path
import signal
import socket
import threading
import binascii
import random
import string
import time
import json
import hashlib
import base64

class ReplacableString:
    def __init__(self, base_string):
        self.base_string =base_string

    def replacer(self, to_replace, replacer):
        for i in xrange(len(self.base_string)):
            if to_replace == self.base_string[i:i+len(to_replace)]:
                self.base_string = self.base_string[:i] + replacer + self.base_string[i+len(to_replace):]

    def __str__(self):
        return str(self.base_string)

def Replacer(self, find, replace):
    return(replace.join(self.split(find)))

def RandomString(N):
    return b''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(N))

def rlf(s):
    s = Replacer(s,b'\r\n',b'')
    s = Replacer(s,b'\n',b'')
    return s 

def utobs(s):
    return s.encode()

def utoba(s):
    d = {}
    for k in s:
        k = rlf(utobs(k))
        d[k] = s[k]
    return d

def md5(N):
    m = hashlib.md5()
    m.update(N)
    return m.hexdigest()

def b64to32_address(key):
    raw_key = base64.b64decode(key, '-~')
    hash = hashlib.sha256(raw_key)
    base32_hash = base64.b32encode(hash.digest())
    return (b'%s.b32.i2p' % base32_hash.lower().replace('=', ''))

def onion_string(key):
    key = hashlib.sha1(key).digest()[:10]
    return base64.b32encode(key).decode('utf-8').lower()

def onion_string_bytes(key):
    key = onion_string(key)
    return utobs(key)

def url_encode(url):
    url = Replacer(url,b':',b'%3A')
    url = Replacer(url,b'/',b'%2F')
    return url

def http_request_nonce(host='127.0.0.1', port=4444, nonce="3"):
    if nonce != "3":
       return nonce
    #print host
    #print port
    mytime = md5(str(time.time()).encode())
    re = (b'GET http://%s.i2p/?i2paddresshelper=LPJyAF6f-tMEgon97AufVfU0TL-rKc-tkPpLymnCzFRnsKsrWSfFyAmPU3ps8oJEgri9cxI87M5OA6goZX0TAnr7u7sXiTUPNRs2k2BpQRO2v1e2xD1biqiarcs4AEKPrSH3nZjWoxqbpOpg8vyce4YvEtenKlvB1x40OjjGl2mrNw3ZjcdOQKIune14fxr5vsPmSJB1eSUM8LUygJbZ~zvWBCNnKG0S7igcYPADRQYsMXKTb~N7w2NJVOuYJoUO9-kjKAYD7To5bvLG6zWlPFzQiOcjtGaI5mZ6zEQH44PBcaN2qX5bpJjR~q7ZkrS5rJeU~4flqx4PlPsklFKTV0SqKl0UFwxFaznbrn3~sY~b6vJuqSeOv0GbR8ijG5S0B967Uars4C2Yx8eH~8iXGeUhUcrKOQIJ5qFPFo9u105Pu74cNcJa9TUd6CDbsrcn4vy5w1BNCKc21yRPf4hpPTkzrqDsxvi4-vvseYPndHrAPBohVHztcDb6d3OhlwhgBQAEAAcAAA== HTTP/1.1\r\nHost: %s.i2p\r\nUser-Agent: Mozilla/5.0 (X11 Linux.x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: utf-8\r\nDNT: 1\r\nX-Forwarded-For: 43.5.124.236\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n' % (mytime,mytime))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print host
    print port
    sock.connect((host,port))
    sended = 0
    i = 0
    data_len = len(re)
    while i < data_len:
       sended = sock.send(re[i:],0)
       if sended == 0:
          break
       i = i + sended
    recv_data = b''
    chunks = []
    chunk = b''
    loop = True
    loop_cancel = False
    while loop:
        try:
            chunk = sock.recv(1024)
            if not chunk:
               if loop_cancel:
                  loop = False
               continue
            chunks.append(chunk)
            if b'</html>' in chunk:
                loop_cancel = True
        except:
            break
    sock.close()
    recv_data = b''.join(chunks)
    recv_data = recv_data.encode()
    recv_data = Replacer(recv_data,b'\r\n','')
    recv_data = Replacer(recv_data,b'\n','')
    recv_data = recv_data.split(b'<input type="hidden" name="nonce" value="')
    if len(recv_data) > 1:
       recv_data = recv_data[1].split(b'">')
       if len(recv_data) > 0:
          recv_data = recv_data[0]
       else:
          return "3"
    else:
       return "3"
    return recv_data
    

def http_request_proxy(host,dest,router=b'router',nonce=b'3542682309546403524'):
  url_encoded = url_encode((b'http://%s.i2p/' % (host)))
  str = (b'GET http://proxy.i2p/add?host=%s.i2p&dest=%s&nonce=%s&router=%s&url=%s HTTP/1.1\r\n' % (host,dest,nonce,router,url_encoded))
  str = (b'%s%s\r\n' % (str,b'Host: proxy.i2p')) 
  str = (b'%s%s\r\n' % (str,b'User-Agent: Mozilla/5.0 (X11 Linux.x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'))
  str = (b'%s%s\r\n' % (str,b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'))
  str = (b'%s%s\r\n' % (str,b'Accept-Language: en-US,en;q=0.5'))
  str = (b'%s%s\r\n' % (str,b'Accept-Encoding: utf-8'))
  str = (b'%s%s\r\n' % (str,b'DNT: 1'))
  str = (b'%s%s\r\n' % (str,b'X-Forwarded-For: 43.5.124.236'))
  str = (b'%s%s\r\n' % (str,b'Connection: keep-alive'))
  str = (b'%s%s\r\n\r\n' % (str,b'Upgrade-Insecure-Requests: 1'))
  return str

def http_request_proxy_add(host,dest,i2p_host=b'127.0.0.1', i2p_port=4444, i2p_nonce=b'3542682309546403524'):
    router = http_request_proxy(host,dest,b'router',i2p_nonce)
    private = Replacer(router,b'=router',b'=private')
    master = Replacer(router,b'=router',b'=master')
    router_len = len(router)
    private_len = len(private)
    master_len = len(master)
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((i2p_host,i2p_port))
    i = 0
    sended = 0
    while i < router_len:
          try:
              sended = sock.send(router[i:],0)
              if sended == 0:
                 break
              i = i + sended
          except:
              break

    recv_data = b''
    chunks = []
    chunk = b''
    loop = True
    loop_cancel = False

    while loop:
        try:
            chunk = sock.recv(1024)
            if not chunk:
               if loop_cancel:
                  loop = False
               continue
            chunks.append(chunk)
            if b'</html>' in chunk:
                loop_cancel = True
        except:
            break

    recv_data = b''.join(chunks)
    chunks = []
    loop_cancel = False
    loop = True
    data_router = recv_data
    recv_data = b''

    sock.close()
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((i2p_host,i2p_port))
    i = 0
    while i < private_len:
          try:  
              sended = sock.send(private[i:],0)
              if sended == 0:
                 break
              i = i + sended
          except:
              break  

    while loop:
        try:
            chunk = sock.recv(1024)
            if not chunk:
               if loop_cancel:
                  loop = False
               continue
            chunks.append(chunk)
            if b'</html>' in chunk:
                loop_cancel = True
        except:  
            break
    
    recv_data = b''.join(chunks)
    chunks = []
    loop_cancel = False
    loop = True
    data_private = recv_data
    recv_data = b''     

    sock.close()
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((i2p_host,i2p_port))
    i = 0
    while i < master_len:
          try:  
              sended = sock.send(master[i:],0)
              if sended == 0:
                 break
              i = i + sended
          except:
              break

    while loop:
        try:
            chunk = sock.recv(1024)
            if not chunk:
               if loop_cancel:
                  loop = False
               continue
            chunks.append(chunk)
            if b'</html>' in chunk:
                loop_cancel = True
        except:
            break

    recv_data = b''.join(chunks)
    chunks = []
    loop_cancel = False
    loop = True
    data_master = recv_data

    sock.close()

def http_request_proxy_add_thread(host,dest,i2p_host=b'127.0.0.1', i2p_port=4444, i2p_nonce=b'3542682309546403524'):
    try:
        thread = threading.Thread(target=http_request_proxy_add, args=(host, dest, i2p_host, i2p_port, i2p_nonce))
        thread.setDaemon(True)
        thread.start()
    except:
        pass


class i2p_socket_ex(socket._socketobject):
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, _sock=None, pkey=b'',port_range_faktor=10):
        self._sock = _sock
        if self._sock == None:
            self._sock = socket._realsocket(family, type, proto)
        else:
            self._sock = _sock

        socket._socketobject.__init__(self,family, type, proto, self._sock)

        self.pkey_len = len(pkey)
        if self.pkey_len > 0:
           self.pkey = pkey
           self.pkey_send = (b'%s\n' % self.pkey)
           self.pkey_send_len = len(self.pkey_send)
           self.paddr = ''
           self.paddr_onion = ''
           self.pkey_len_sended = 0
           self.port_range_faktor = int(port_range_faktor)
           self.i2p_host = ''
           self.i2p_port = 0
           self.i2p_port_new = 0
           if not (self.pkey.endswith(b'.i2p') or self.pkey.endswith('.i2p')):
               try:
                  self.paddr = b64to32_address(self.pkey)
                  self.paddr_onion = onion_string_bytes(self.paddr)
               except:
                  pass
        if self.pkey_len > 0:
           setattr(self, 'old_send', getattr(self, 'send'))
           setattr(self, 'old_connect', getattr(self, 'connect'))
           setattr(self, 'old_getsockname', getattr(self, 'getsockname'))
           setattr(self, 'old_close', getattr(self, 'close'))
           setattr(self, 'send', getattr(self, 'i2p_send'))
           setattr(self, 'connect', getattr(self, 'i2p_connect'))
           setattr(self, 'close', getattr(self, 'i2p_close'))
           setattr(self, 'getsockname', getattr(self, 'i2p_getsockname')) 
    
    def i2p_send(self, data, flags=0):
        try:
            while self.pkey_len_sended < self.pkey_send_len:
               sended = self.old_send(self.pkey_send[self.pkey_len_sended:],flags)
               if sended == 0:
                  self.pkey_len_sended = 0
                  return 0
               self.pkey_len_sended = self.pkey_len_sended + sended
            length = len(data)
            i = 0
            sended = 0
            while i < length:
               sended = self.old_send(data[i:],flags)
               if sended == 0:
                  return i
               i = i + sended
            return i
        except:
            return 0

    def i2p_connect(self,addr):
        have_host = False
        have_port = False
        self.i2p_host = 0
        self.i2p_port = 0
        for k in addr:
            if not have_host:
               have_host = True
               self.i2p_host = k
               continue
            elif not have_port:
               have_port = True
               self.i2p_port = k
               continue
            else: 
               break
        
        self.i2p_port = int(self.i2p_port)
        self.i2p_port_new = self.i2p_port + self.port_range_faktor
        self.old_connect((self.i2p_host, self.i2p_port_new))

    def i2p_getsockname(self):
         if self.i2p_port_new == 0:
              return self.old_getsockname()
         else:
              return (self.i2p_host, self.i2p_port_new)
 
    def i2p_close(self):
        self.pkey_len_sended = 0
        self.old_close()

class i2p_socket:
    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def i2p_connect(self, host, port):
        self.sock.connect((host, port))
        self.connected = True

    def i2p_send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                return totalsent
            totalsent = totalsent + sent
        return totalsent

    def i2p_sendall(self, msg):
        self.sock.sendall(msg)

    def i2p_receive(self, RECV_BUFSIZE=4096):
        while True:
            data = self.sock.recv(RECV_BUFSIZE)
            if not data:
                    return ''
            return data

    def i2p_receive_until_timeouted(self,RECV_BUFSIZE=4096,TIMEOUT=5.0):
        chunks = []
        self.sock.settimeout(TIMEOUT)
        while True:
            try:
                  data = self.sock.recv(RECV_BUFSIZE)
                  if not data:
                        continue
                  chunks.append(data)
            except socket.timeout as err:
                  break
        self.sock.settimeout(None)
        ret = ''.join(chunks)
        return ret

    def i2p_receive_until_linefeed_counted(self,RECV_BUFSIZE=4096, COUNT=1, TIMEOUT=5.0):
        chunks = []
        c = 0
        while True:
             try:
                 data = self.sock.recv(RECV_BUFSIZE)
                 if not data:  
                    continue
                 chunks.append(data)
                 if b'\n' in data:
                    c = c + 1
                    if c >= COUNT:
                       self.sock.settimeout(TIMEOUT)
             except socket.timeout as err:
                     break
        self.sock.settimeout(None)
        ret = ''.join(chunks)
        return ret

    def i2p_receive_until_ret_code(self,RECV_BUFSIZE=4096, TIMEOUT=30.0, ret_code_ok=b'OK', ret_code_error=b'ERROR'):
        chunks = []
        self.sock.settimeout(TIMEOUT)
        while True:
             try:
                 data = self.sock.recv(RECV_BUFSIZE)
                 if not data:
                    continue
                 chunks.append(data)
                 end = ''.join(chunks)
                 if ((ret_code_ok in end) or (ret_code_error in end)):
                    if '\n' in end:
                       break
             except socket.timeout as err:
                  break
        end = ''.join(chunks)
        ret = end
        end = ret

        self.sock.settimeout(None)
        return end

    def i2p_receive_until_linefeed_timeouted(self,RECV_BUFSIZE=4096,TIMEOUT=5.0):
        chunks = []
        self.sock.settimeout(TIMEOUT)
        while True:
            try:
                  data = self.sock.recv(RECV_BUFSIZE)
                  if not data:
                        continue
                  chunks.append(data)
                  if b'\n' in data:
                        break
            except socket.timeout as err:
                  break
        self.sock.settimeout(None)
        ret = ''.join(chunks)
        return ret

    def i2p_receive_chunked(self,RECV_SIZE=4096):
        chunks = []
        tot_recv = 0
        chunklen = 0
        while tot_recv < RECV_SIZE:
             chunk = self.i2p_receive(RECV_SIZE)
             chunklen = len(chunk)
             if chunklen > 0:
                chunks.append(chunk)
                tot_recv = tot_recv + chunklen
             else:
                return ''
        return ''.join(chunks)

    def i2p_receive_message_until_timeouted(self,msg,TIMEOUT=10.0):
        chunks = []
        next = True
        for i, c in enumerate(msg):
             while next:
                nc = self.i2p_receive_timeouted(1,TIMEOUT)
                if nc:
                   if nc == c:
                      chunks.append(nc)
                      next = False
                else:
                   ret = ''.join(chunks)
                   ret = Replacer(ret,'\r\n','')
                   ret = Replacer(ret,'\n','')
                   return ret
             next = True
        ret = ''.join(chunks)
        return ret

    def i2p_close(self):
        self.sock.close()
    
    def getSock(self):
        return self.sock

class i2p_bob:
    def __init__(self, i2p_host=b'127.0.0.1', i2p_port=2827, inhost=b'127.0.0.1', outhost=b'127.0.0.1', inport=3840, outport=3841, insrvid=b'ear', outsrvid=b'ear_out', quiet_in=False, quiet_out=False):
        self.i2p_host = i2p_host       
        self.i2p_port = i2p_port
        self.inhost = inhost
        self.outhost = outhost
        self.inport = inport
        self.outport = outport
        self.insrvid = insrvid
        self.outsrvid = outsrvid
        self.outpkey = ''
        self.outpaddr = ''
        self.outpaddr_onion = ''
        self.inpkey = ''
        self.inpaddr = ''
        self.inpaddr_onion = ''
        self.i2p_sock_out = ''
        self.i2p_sock_in = ''
        self.i2p_sock_load = ''
        self.started = False
        self.data = ''
        self.out = True
        self.count = 1
        self.ret = False
        self.quiet_in = quiet_in
        self.quiet_out = quiet_out
        self.in_is_out = self.insrvid == self.outsrvid
        if self.in_is_out:
           if self.quiet_in or self.quiet_out:
              self.quiet_in = self.quiet_out = True

    def geti2p_bob(self):
        ret = {}
        ret["started"] = self.started
        ret["i2p_host"] = self.i2p_host
        ret["i2p_port"] = self.i2p_port
        ret["inhost"] = self.inhost
        ret["outhost"] = self.outhost
        ret["inport"] = self.inport
        ret["outport"] = self.outport
        ret["insrvid"] = self.insrvid
        ret["outsrvid"] = self.outsrvid
        ret["outpkey"] = self.outpkey
        ret["inpkey"] = self.inpkey
        ret["quiet_in"] = self.quiet_in
        ret["quiet_out"] = self.quiet_out
        ret["in_is_out"] = self.in_is_out
        ret["outpaddr"] = self.outpaddr
        ret["inpaddr"] = self.inpaddr
        ret["outpaddr_onion"] = self.outpaddr_onion
        ret["inpaddr_onion"] = self.inpaddr_onion
        return ret

    def seti2p_bob(self,ret):
        self.started = ret["started"]
        self.i2p_host = ret["i2p_host"]
        self.i2p_port = ret["i2p_port"]
        self.inhost = ret["inhost"]
        self.outhost = ret["outhost"]
        self.inport = ret["inport"]
        self.outport = ret["outport"]
        self.insrvid = ret["insrvid"]
        self.outsrvid = ret["outsrvid"]
        self.outpkey = ret["outpkey"]
        self.inpkey = ret["inpkey"]
        self.quiet_in = ret["quiet_in"]
        self.quiet_out = ret["quiet_out"]
        self.in_is_out = ret["in_is_out"]
        self.outpaddr = ret["outpaddr"]
        self.inpaddr = ret["inpaddr"]
        self.outpaddr_onion = ret["outpaddr_onion"]
        self.inpaddr_onion = ret["inpaddr_onion"]


    def dumpi2p_bob(self):
        ret = self.geti2p_bob()
        str = binascii.b2a_base64(json.dumps(ret))
        return str       

    def loadsi2p_bob(self,reti):
        ret = binascii.a2b_base64(reti)
        ret = json.loads(ret)
        return ret 

    def savei2p_bob(self,path):
        str = self.dumpi2p_bob()
        fp = open(path, 'wb')
        fp.write(str)
        fp.close()

    def loadi2p_bob(self,path):
        fp = open(path, 'rb')
        str = fp.read()
        fp.close()
        ret = loadsi2p_bob(self,str)
        self.seti2p_bob(ret)

    def outhost_message(self):
        return b'OK outhost set'

    def outport_message(self):
        return b'OK outbound port set'

    def tun_start_message(self):
        return b'OK tunnel starting'

    def tun_stop_message(self):
        return b'OK tunnel stopping'

    def clear_message(self):
        return b'OK cleared'

    def setnick_message(self,nick):
        return (b'OK Nickname set to %s' % nick)

    def bye_message(self):
        return b'OK Bye!'

    def parse_data_msg(self,data_message):
        data_message = Replacer(data_message,b'DATA NICKNAME', b'DATA_NICKNAME')
        data_message = Replacer(data_message,b'\r\n',b'<LF>')
        data_message = Replacer(data_message,b'\n', b'<LF>')
        data_message = Replacer(data_message,b': ', b'<DOUBLE_POINT>')
        data_message = Replacer(data_message,b' ', b'<SPACE>')
        ret = {}
        ret["msg"] = ''
        ret["entrys_1"] = {}
        ret["entrys_2"] = {}
        ret["entrys_1"]["DATA NICKNAME"] = ''
        ret["entrys_1"]["STARTING"] = ''
        ret["entrys_1"]["RUNNING"] = ''
        ret["entrys_1"]["STOPPING"] = ''
        ret["entrys_1"]["KEYS"] = ''
        ret["entrys_1"]["QUIET"] = ''
        ret["entrys_1"]["INPORT"] = ''
        ret["entrys_1"]["INHOST"] = ''
        ret["entrys_1"]["OUTPORT"] = ''
        ret["entrys_1"]["OUTHOST"] = ''
        ret["entrys_2"]["DATA NICKNAME"] = ''
        ret["entrys_2"]["STARTING"] = ''
        ret["entrys_2"]["RUNNING"] = ''
        ret["entrys_2"]["STOPPING"] = ''
        ret["entrys_2"]["KEYS"] = ''
        ret["entrys_2"]["QUIET"] = ''
        ret["entrys_2"]["INPORT"] = ''
        ret["entrys_2"]["INHOST"] = ''
        ret["entrys_2"]["OUTPORT"] = ''
        ret["entrys_2"]["OUTHOST"] = ''

        ret["entrys_1_len"] = 0
        ret["entrys_2_len"] = 0
        ret["rows"] = 0
        #print(data_message)
        datas = data_message.split(b'<LF>')
        length = len(datas) - 1
        if length > 3:
           c = 0
           ne = []
           le = length - 1
           in_set = False
           out_set = False
           while c < le:
              if self.outsrvid in datas[c]:
                    en = datas[c].split(b'<SPACE>')
                    dn = en[0].split(b'<DOUBLE_POINT>')[1]
                    if dn == self.outsrvid:
                       out_set = True
                       ne.append(datas[c])  
              elif self.insrvid in datas[c]:
                    en = datas[c].split(b'<SPACE>')
                    dn = en[0].split(b'<DOUBLE_POINT>')[1]
                    if dn == self.insrvid:
                       in_set = True
                       ne.append(datas[c])
              if in_set and out_set:
                 break
              c = c + 1
           if in_set and out_set:
              ne.append(datas[le])
              length = len(ne)
              datas = ne
        ret["rows"] = length
        if length == 1:
           ret["msg"] = Replacer(datas[0],b'<SPACE>', b' ')
        elif length == 2:
           entrys = datas[0].split(b'<SPACE>')
           ret["entrys_1_len"] = len(entrys)
           if not ret["entrys_1_len"] == 10:
              return ret
           ret["entrys_1"]["DATA NICKNAME"] = (entrys[0].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["STARTING"] = (entrys[1].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["RUNNING"] = (entrys[2].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["STOPPING"] = (entrys[3].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["KEYS"] = (entrys[4].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["QUIET"] = (entrys[5].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["INPORT"] = (entrys[6].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["INHOST"] = (entrys[7].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["OUTPORT"] = (entrys[8].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["OUTHOST"] = (entrys[9].split(b'<DOUBLE_POINT>'))[1]
           ret["msg"] = Replacer(datas[1],b'<SPACE>', b' ')
        elif length == 3:
           entrys_1 = datas[0].split(b'<SPACE>')
           entrys_2 = datas[1].split(b'<SPACE>')
           ret["entrys_1_len"] = len(entrys_1)
           ret["entrys_2_len"] = len(entrys_2)
           if not ret["entrys_1_len"] == 10:
              return ret
           if not ret["entrys_2_len"] == 10:
              return ret

           entrys = entrys_1
           ret["entrys_1"]["DATA NICKNAME"] = (entrys[0].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["STARTING"] = (entrys[1].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["RUNNING"] = (entrys[2].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["STOPPING"] = (entrys[3].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["KEYS"] = (entrys[4].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["QUIET"] = (entrys[5].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["INPORT"] = (entrys[6].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["INHOST"] = (entrys[7].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["OUTPORT"] = (entrys[8].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_1"]["OUTHOST"] = (entrys[9].split(b'<DOUBLE_POINT>'))[1]
          # print (ret["entrys_1"]["DATA NICKNAME"])
           entrys = entrys_2        
           ret["entrys_2"]["DATA NICKNAME"] = (entrys[0].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["STARTING"] = (entrys[1].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["RUNNING"] = (entrys[2].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["STOPPING"] = (entrys[3].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["KEYS"] = (entrys[4].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["QUIET"] = (entrys[5].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["INPORT"] = (entrys[6].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["INHOST"] = (entrys[7].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["OUTPORT"] = (entrys[8].split(b'<DOUBLE_POINT>'))[1]
           ret["entrys_2"]["OUTHOST"] = (entrys[9].split(b'<DOUBLE_POINT>'))[1]
           ret["msg"] = Replacer(datas[2],b'<SPACE>', b' ')
           #print (ret["entrys_2"]["DATA NICKNAME"])
        else:
           return ret
        return ret
 
    def get_data_message(self,sock,RECV_BUFSIZE=4096,TIMEOUT=10.0):
        sock.i2p_send(b'list\n')
        data_message = sock.i2p_receive_until_timeouted(RECV_BUFSIZE,TIMEOUT)
        ret = self.parse_data_msg(data_message)
        if ret["rows"] > 1:
           ret["entrys_1"]["STARTING"] = ret["entrys_1"]["STARTING"] == 'true'
           ret["entrys_1"]["RUNNING"] = ret["entrys_1"]["RUNNING"] == 'true'
           ret["entrys_1"]["STOPPING"] = ret["entrys_1"]["STOPPING"] == 'true'
           ret["entrys_1"]["KEYS"] = ret["entrys_1"]["KEYS"] == 'true'
           ret["entrys_1"]["QUIET"] = ret["entrys_1"]["QUIET"] == 'true'

        if ret["rows"] > 2:    
           ret["entrys_2"]["STARTING"] = ret["entrys_2"]["STARTING"] == 'true'
           ret["entrys_2"]["RUNNING"] = ret["entrys_2"]["RUNNING"] == 'true'
           ret["entrys_2"]["STOPPING"] = ret["entrys_2"]["STOPPING"] == 'true'
           ret["entrys_2"]["KEYS"] = ret["entrys_2"]["KEYS"] == 'true'
           ret["entrys_2"]["QUIET"] = ret["entrys_2"]["QUIET"] == 'true'
        return ret

    def load(self,check=True):
        if self.started:
           return True
        # load connection
        self.i2p_sock_load = i2p_socket()
        self.i2p_sock_load.i2p_connect(self.i2p_host,self.i2p_port)
        data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
        li2p = self.geti2p_bob()
        data = Replacer(data,b'\r\n',b' ')
        data = Replacer(data,b'\n', b' ')
        if not data.startswith(b'BOB 00.00.10 OK'):
            print("ERROR _1")
            li2p["started"] = False
            self.seti2p_bob(li2p)
            self.i2p_sock_load.i2p_close()
            return False

        ret = self.get_data_message(self.i2p_sock_load)
        rows = ret["rows"]
        entrys_1_len = ret["entrys_1_len"]
        entrys_2_len = ret["entrys_2_len"]
        msg = ret["msg"]
        entrys_1 = ret["entrys_1"]
        entrys_2 = ret["entrys_2"]
        ret["e_running"] = {}
        ret["e_running"]["out_1"] = False
        ret["e_running"]["out_2"] = False
        ret["e_running"]["in_1"] = False
        ret["e_running"]["in_2"] = False
        in_set = False
        out_set = False
        quiet = False
        quiet_is_set = False
        if rows > 1 and entrys_1_len == 10: 
           if (not out_set) and (entrys_1["DATA NICKNAME"] == self.outsrvid):
                 srvid = self.outsrvid
                 port = (b'%s' % self.outport)
                 host = self.outhost
                 host_str = "OUTHOST"
                 port_str = "OUTPORT"
                 hstr = "outhost"
                 pstr = "outport"
                 entrys = entrys_1
                 pkey = 'outpkey'
                 pkey_addr = 'outpaddr'
                 pkey_addr_onion = 'outpaddr_onion'
                 erunkey = "out_1"
                 quiet = self.quiet_out
                 ret["e_running"][erunkey] = False
                 host_not_set = host == b'not_set' or host == 'not_set'
                 port_not_set = port == b'not_set' or port == 'not_set'
                 out_set = True
           elif (not in_set) and (entrys_1["DATA NICKNAME"] == self.insrvid):
                 srvid = self.insrvid
                 port = (b'%s' % self.inport)
                 host = self.inhost
                 host_str = "INHOST"
                 port_str = "INPORT"
                 hstr = "inhost"
                 pstr = "inport"
                 entrys = entrys_1
                 pkey = 'inpkey'
                 pkey_addr = 'inpaddr'
                 pkey_addr_onion = 'inpaddr_onion'
                 erunkey = "in_1"
                 quiet = self.quiet_in
                 ret["e_running"][erunkey] = False
                 host_not_set = host == b'not_set' or host == 'not_set'
                 port_not_set = port == b'not_set' or port == 'not_set'
                 in_set = True
           else:
                 self.i2p_sock_load.i2p_close()
                 li2p["started"] = False
                 self.seti2p_bob(li2p)
                 return False

           self.i2p_sock_load.i2p_send((b'getnick %s\n' % srvid))
           data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
           if data.startswith(b'OK'):
              if entrys["KEYS"]:
                 self.i2p_sock_load.i2p_send((b'getkeys %s\n' % srvid))
                 data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                 if data.startswith(b'OK'):
                    a = data.split()
                    if len(a) == 2:
                       li2p[pkey] = a[1]
                       li2p[pkey_addr] = b64to32_address(li2p[pkey])
                       li2p[pkey_addr_onion] = onion_string_bytes(li2p[pkey_addr])
                       self.seti2p_bob(li2p)
              else:
                 self.i2p_sock_load.i2p_send((b'newkeys %s\n' % srvid))
                 data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                 if data.startswith(b'OK'):
                    a = data.split()
                    if len(a) == 2:
                       li2p[pkey] = a[1]
                       li2p[pkey_addr] = b64to32_address(li2p[pkey])
                       li2p[pkey_addr_onion] = onion_string_bytes(li2p[pkey_addr])
                       self.seti2p_bob(li2p)
              if check == True:
                 if not (host == entrys[host_str]):
                    self.i2p_sock_load.i2p_send((b'%s %s\n' % (hstr,host)))
                    data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()

                 if not (port == entrys[port_str]):
                    self.i2p_sock_load.i2p_send((b'%s %s\n' % (pstr,port)))
                    data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
              else:
                 host = entrys[host_str]
                 port = entrys[port_str]
                 li2p[hstr] = (b'%s' % host)
                 if port != b'not_set':
                    li2p[pstr] = int(port)
                 else:
                    li2p[pstr] = b'not_set'
                 self.seti2p_bob(li2p)
             
              if not entrys["QUIET"] and quiet:
                    self.i2p_sock_load.i2p_send(b'quiet true\n')
                    data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                    if self.in_is_out: 
                       quiet_is_set = True

              if not self.in_is_out:
                 if entrys["STARTING"] or entrys["RUNNING"]:
                    ret["e_running"][erunkey] = True
                 else:
                    self.i2p_sock_load.i2p_send((b'start\n'))
                    data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                    if data.startswith(b'OK'):
                       ret["e_running"][erunkey] = True
                           

        if rows > 2 and entrys_2_len == 10:
            if (not out_set) and (entrys_2["DATA NICKNAME"] == self.outsrvid):
                 srvid = self.outsrvid
                 port = (b'%s' % self.outport)
                 host = self.outhost
                 host_str = "OUTHOST"
                 port_str = "OUTPORT"
                 hstr = "outhost"
                 pstr = "outport"
                 entrys = entrys_2
                 pkey = 'outpkey'
                 pkey_addr = 'outpaddr'
                 pkey_addr_onion = 'outpaddr_onion'
                 if (self.in_is_out and quiet_is_set):
                    quiet = False
                 else:
                    quiet = self.quiet_out
                 erunkey = "out_2"
                 ret["e_running"][erunkey] = False
                 host_not_set = host == b'not_set' or host == 'not_set'
                 port_not_set = port == b'not_set' or port == 'not_set'
                 out_set = True
            elif (not in_set) and (entrys_2["DATA NICKNAME"] == self.insrvid):
                 srvid = self.insrvid
                 port = (b'%s' % self.inport)
                 host = self.inhost
                 host_str = "INHOST"
                 port_str = "INPORT"
                 hstr = "inhost"
                 pstr = "inport"
                 entrys = entrys_2
                 pkey = 'inpkey'
                 pkey_addr = 'inpaddr'
                 pkey_addr_onion = 'inpaddr_onion'
                 if (self.in_is_out and quiet_is_set):                    
                    quiet = False
                 else:
                    quiet = self.quiet_in
                 erunkey = "in_2"
                 ret["e_running"][erunkey] = False
                 host_not_set = host == b'not_set' or host == 'not_set'
                 port_not_set = port == b'not_set' or port == 'not_set'
                 in_set = True
            else:
                 li2p["started"] = False
                 self.seti2p_bob(li2p)
                 self.i2p_sock_load.i2p_close()
                 return False

            self.i2p_sock_load.i2p_send((b'getnick %s\n' % srvid))
            data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
            if data.startswith(b'OK'):
              if entrys["KEYS"]:  
                 self.i2p_sock_load.i2p_send((b'getkeys %s\n' % srvid))
                 data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                 if data.startswith(b'OK'):
                    a = data.split()
                    if len(a) == 2: 
                       li2p[pkey] = a[1]
                       li2p[pkey_addr] = b64to32_address(li2p[pkey])
                       li2p[pkey_addr_onion] = onion_string_bytes(li2p[pkey_addr])
                       self.seti2p_bob(li2p)
              else:
                 self.i2p_sock_load.i2p_send((b'newkeys %s\n' % srvid))
                 data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                 if data.startswith(b'OK'):
                    a = data.split()
                    if len(a) == 2: 
                       li2p[pkey] = a[1]
                       li2p[pkey_addr] = b64to32_address(li2p[pkey])
                       li2p[pkey_addr_onion] = onion_string_bytes(li2p[pkey_addr])
                       self.seti2p_bob(li2p)   
           
            if check == True:
                if not (host == entrys[host_str]):
                    self.i2p_sock_load.i2p_send((b'%s %s\n' % (hstr,host)))
                    data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()

                if not (port == entrys[port_str]):
                    self.i2p_sock_load.i2p_send((b'%s %s\n' % (pstr,port)))
                    data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
            else:
                host = entrys[host_str]
                port = entrys[port_str]
                li2p[hstr] = (b'%s' % host)
                li2p[pstr] = int(port)
                self.seti2p_bob(li2p)

            if not entrys["QUIET"] and quiet:
                 self.i2p_sock_load.i2p_send(b'quiet true\n') 
                 data = self.i2p_sock_load.i2p_receive_until_linefeed_counted() 

            if entrys["STARTING"] or entrys["RUNNING"]:
                 ret["e_running"][erunkey] = True
            else:
                 self.i2p_sock_load.i2p_send((b'start\n'))
                 data = self.i2p_sock_load.i2p_receive_until_linefeed_counted()
                 if data.startswith(b'OK'):
                    ret["e_running"][erunkey] = True
              
       
        if (ret["e_running"]["out_1"] or ret["e_running"]["out_2"]) and (ret["e_running"]["in_1"] or ret["e_running"]["in_2"]):
           li2p["started"] = True
           self.seti2p_bob(li2p) 
           self.i2p_sock_load.i2p_close()
           return True

        li2p["started"] = False
        self.seti2p_bob(li2p)
        self.i2p_sock_load.i2p_close()
        return False

    def start(self):
        if self.started:
           return True

        quiet = False
        # out connection
        self.i2p_sock_out = i2p_socket()
        self.i2p_sock_out.i2p_connect(self.i2p_host,self.i2p_port)
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        data = Replacer(data,b'\r\n',b' ')
        data = Replacer(data,b'\n', b' ')
        outhost_not_set = self.outhost == b'not_set' or self.outhost == 'not_set'
        inhost_not_set = self.inhost == b'not_set' or self.inhost == 'not_set'
        outport_not_set = self.outport == b'not_set' or self.outport == 'not_set'
        inport_not_set = self.inport == b'not_set' or self.inport == 'not_set'
        outhost_set = not outhost_not_set
        inhost_set = not inhost_not_set
        outport_set = not outport_not_set
        inport_set = not inport_not_set

        ok1 = True
        ok2 = True

        if not data.startswith(b'BOB 00.00.10 OK'):
            print("ERROR _1")
            self.i2p_sock_out.i2p_close()
            return False

        self.i2p_sock_out.i2p_send((b'setnick %s\n' % self.outsrvid))
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _2")
            self.i2p_sock_out.i2p_close()
            return False
  
        self.i2p_sock_out.i2p_send(b'newkeys\n')
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR_3")
            self.i2p_sock_out.i2p_close() 
            return False

        a = data.split()
        if len(a) == 2:
           self.outpkey = a[1]
           self.outpaddr = b64to32_address(self.outpkey)
           self.outpaddr_onion = onion_string_bytes(self.outpaddr)
        else:
            print("ERROR 1_2")
            self.i2p_sock_out.i2p_close()
            return False

        if outhost_set:
           self.i2p_sock_out.i2p_send((b'outhost %s\n' % self.outhost))
           data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
           if not data.startswith(b'OK'):
              print("ERROR_4")
              self.i2p_sock_out.i2p_close()
              return False        
        else:
           ok1 = False

        if outport_set:
           self.i2p_sock_out.i2p_send((b'outport %s\n' % self.outport))
           data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
           if not data.startswith(b'OK'):
              print("ERROR_5")
              self.i2p_sock_out.i2p_close()
              return False
        else:
           ok2 = False

        if self.quiet_out:
           self.i2p_sock_out.i2p_send(b'quiet true\n')
           data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
           if self.in_is_out: 
              quiet = False       

        oks = ok1 and ok2
        # self.in_is_out = self.insrvid == self.outsrvid 
        if ((not self.in_is_out) and (oks)):
           self.i2p_sock_out.i2p_send(b'start\n')
           data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
           if not data.startswith(b'OK'):
              print("ERROR _6")
              self.i2p_sock_out.i2p_close()
              return False

           self.i2p_sock_out.i2p_send(b'quit\n')
           data = self.i2p_sock_out.i2p_receive()

           self.i2p_sock_out.i2p_close()

        ok1 = ok2 = True
        # in connection
        self.i2p_sock_in = i2p_socket()
        self.i2p_sock_in.i2p_connect(self.i2p_host,self.i2p_port)
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        data = Replacer(data,b'\r\n',b' ')
        data = Replacer(data,b'\n', b' ')
        if not data.startswith(b'BOB 00.00.10 OK'):
            print("ERROR _IN_1")
            self.i2p_sock_in.i2p_close()
            return False

        if not self.in_is_out:
           self.i2p_sock_in.i2p_send((b'setnick %s\n' % self.insrvid))
        else:
           self.i2p_sock_in.i2p_send((b'getnick %s\n' % self.insrvid))
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _IN_2")
            self.i2p_sock_in.i2p_close()
            return False

        if not self.in_is_out:
            self.i2p_sock_in.i2p_send(b'newkeys\n')
        else:
            self.i2p_sock_in.i2p_send((b'getkeys %s\n' % self.insrvid))
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _IN_3")
            self.i2p_sock_in.i2p_close()
            return False
        a = data.split()
        if len(a) == 2:
           self.inpkey = a[1]
           self.inpaddr = b64to32_address(self.inpkey) 
           self.inpaddr_onion = onion_string_bytes(self.inpaddr)
        else:
           print("ERROR IN_1_2")
           self.i2p_sock_in.i2p_close()
           return False

        if inhost_set:
           self.i2p_sock_in.i2p_send((b'inhost %s\n' % self.inhost))
           data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
           if not data.startswith(b'OK'):
              print("ERROR _IN_4")
              self.i2p_sock_in.i2p_close()
              return False
        else:
           ok1 = False

        if inport_set:
           self.i2p_sock_in.i2p_send((b'inport %s\n' % self.inport))
           data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
           if not data.startswith(b'OK'):
              print("ERROR _IN_5")
              self.i2p_sock_in.i2p_close()
              return False
        else:
            ok2 = False

        if not self.in_is_out:
             if self.quiet_in:
                self.i2p_sock_in.i2p_send(b'quiet true\n')
                data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()   
        elif quiet:
             self.i2p_sock_in.i2p_send(b'quiet true\n')
             data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
       
        oks = ok1 and ok2
        if oks:
           self.i2p_sock_in.i2p_send(b'start\n')
           data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
           if not data.startswith(b'OK'):
              print("ERROR _IN_6")
              self.i2p_sock_in.i2p_close()
              return False
        
        self.i2p_sock_in.i2p_send(b'quit\n')
        data = self.i2p_sock_in.i2p_receive()

        self.i2p_sock_in.i2p_close()

        self.started = True
        
    def stop(self):
        if not self.started:
           return False
        
         # out connection
        self.i2p_sock_out = i2p_socket()
        self.i2p_sock_out.i2p_connect(self.i2p_host,self.i2p_port)
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        data = Replacer(data,b'\r\n',b' ')
        data = Replacer(data,b'\n', b' ')
        if not data.startswith(b'BOB 00.00.10 OK'):
            print("ERROR _1")
            self.i2p_sock_out.i2p_close()
            return False

        self.i2p_sock_out.i2p_send((b'getnick %s\n' % self.outsrvid))
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _2")
            self.i2p_sock_out.i2p_close()
            return False

        self.i2p_sock_out.i2p_send(b'stop\n')
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _3")
            self.i2p_sock_out.i2p_close()
            return False

 
        self.i2p_sock_out.i2p_send(b'clear\n')
        data = self.i2p_sock_out.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _4")
            self.i2p_sock_out.i2p_close()
            return False


        self.i2p_sock_out.i2p_send(b'quit\n')
        data = self.i2p_sock_out.i2p_receive()

        self.i2p_sock_out.i2p_close()

        if self.in_is_out:
           self.started = False
           return True

        # in connection
        self.i2p_sock_in = i2p_socket()
        self.i2p_sock_in.i2p_connect(self.i2p_host,self.i2p_port)
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        data = Replacer(data,b'\r\n',b' ')
        data = Replacer(data,b'\n', b' ')
        if not data.startswith(b'BOB 00.00.10 OK'):
            print("ERROR _1")
            self.i2p_sock_in.i2p_close()
            return False

        self.i2p_sock_in.i2p_send((b'getnick %s\n' % self.insrvid))
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _2")
            self.i2p_sock_in.i2p_close()
            return False
        
        self.i2p_sock_in.i2p_send(b'stop\n')
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _3")
            self.i2p_sock_in.i2p_close()
            return False

        self.i2p_sock_in.i2p_send(b'clear\n')
        data = self.i2p_sock_in.i2p_receive_until_linefeed_counted()
        if not data.startswith(b'OK'):
            print("ERROR _4")
            self.i2p_sock_in.i2p_close()
            return False

        self.i2p_sock_in.i2p_send(b'quit\n')
        data = self.i2p_sock_in.i2p_receive()

        self.i2p_sock_in.i2p_close()

        self.started = False

        return True

class FakeI2PTor:
    def __init__(self, port=0, i2p_host='127.0.0.1', i2p_port=2827, port_range_faktor=10):
        if port == 0:
            self.srvid = ''
            self.srvid_in = ''
            self.srvid_out = ''
            self.port = ''
            self.port_range_faktor = port_range_faktor
            self.i2p_host = i2p_host
            self.i2p_port = i2p_port
            self.i2p_bob_i = ''
            self.srvid_in_pkey = ''
            self.srvid_out_pkey = ''
            self.srvid_in_addr = ''
            self.srvid_out_addr = ''
            self.srvid_in_addr_onion = ''
            self.srvid_out_addr_onion = ''
            self.privkey = ''
        elif port_range_faktor == 0:
            self.srvid = (b'%s' % port)   
            self.srvid_in = self.srvid 
            self.srvid_out = self.srvid
            self.srvid_in_pkey = ''
            self.srvid_out_pkey = ''
            self.srvid_in_addr = ''
            self.srvid_out_addr = ''   
            self.srvid_in_addr_onion = ''
            self.srvid_out_addr_onion = ''
            self.port = port
            self.port_range_faktor = port_range_faktor
            self.i2p_host = i2p_host
            self.i2p_port = i2p_port
            self.i2p_bob_i = i2p_bob(self.i2p_host,self.i2p_port,'0.0.0.0', '0.0.0.0', self.port, self.port, self.srvid_in,self.srvid_out,True,True)
            self.i2p_bob_i.load(False)
            self.i2p_bob_i.start()
            reti = self.i2p_bob_i.geti2p_bob()
            self.srvid_in_pkey = reti["inpkey"]
            self.srvid_out_pkey = reti["outpkey"]
            self.srvid_in_addr = reti["inpaddr"]  
            self.srvid_out_addr = reti["outpaddr"]
            self.srvid_in_addr_onion = reti["inpaddr_onion"]
            self.srvid_out_addr_onion = reti["outpaddr_onion"]
            self.privkey = self.dump(reti)
        else:
            #self.srvid = RandomString(16)
            self.srvid = onion_string_bytes(RandomString(1024))
            self.srvid_in = (b'%s' % self.srvid)
            self.srvid_out = (b'%s' % self.srvid)
            self.srvid_in_pkey = ''
            self.srvid_out_pkey = ''
            self.srvid_in_addr = ''
            self.srvid_out_addr = ''     
            self.srvid_in_addr_onion = '' 
            self.srvid_out_addr_onion = ''
            self.port_range_faktor = port_range_faktor
            self.port = port
            self.i2p_host = i2p_host
            self.i2p_port = i2p_port
            self.i2p_bob_i = i2p_bob(self.i2p_host,self.i2p_port,'0.0.0.0', '0.0.0.0', self.port + self.port_range_faktor, self.port, self.srvid_in, self.srvid_out, True, True)
            self.i2p_bob_i.load()
            self.i2p_bob_i.start()
            reti = self.i2p_bob_i.geti2p_bob()
            self.srvid_in_pkey = reti["inpkey"]
            self.srvid_out_pkey = reti["outpkey"]
            self.srvid_in_addr = reti["inpaddr"]
            self.srvid_out_addr = reti["outpaddr"]
            self.srvid_in_addr_onion = reti["inpaddr_onion"]
            self.srvid_out_addr_onion = reti["outpaddr_onion"]
            self.privkey = self.dump(reti)
    
    def getSrvId(self):
        return self.srvid

    def getSrvIdPkey(self):
        return self.srvid_in_pkey

    def getSrvIdAddr(self):
        return self.srvid_in_addr

    def getSrvIdAddrOnion(self):
        return self.srvid_in_addr_onion

    def getPrivKey(self):
        return self.privkey

    def getSrvIdIn(self):
        return self.srvid_in
    
    def getSrvIdOut(self):
        return self.srvid_out
 
    def getSrvIdInPkey(self):
        return self.srvid_in_pkey

    def getSrvIdOutPkey(self):
        return self.srvid_out_pkey

    def getSrvIdInAddr(self):
        return self.srvid_in_addr

    def getSrvIdOutAddr(self):
        return self.srvid_out_addr

    def getSrvIdInAddrOnion(self):
        return self.srvid_in_addr_onion

    def getSrvIdOutAddrOnion(self):
        return self.srvid_out_addr_onion

    def dump(self,retu=None):
        if retu != None:
           reti = retu
        else:
           reti = self.i2p_bob_i.geti2p_bob()
        ret = {}
        ret["srvid"] = self.srvid
        ret["srvid_out"] = self.srvid_out
        ret["srvid_in"] = self.srvid_in
        ret["port"] = self.port
        ret["port_range_faktor"] = self.port_range_faktor
        ret["i2p_host"] = self.i2p_host
        ret["i2p_port"] = self.i2p_port
        ret["srvid_in_pkey"] = reti["inpkey"]
        ret["srvid_out_pkey"] = reti["outpkey"]
        ret["srvid_in_addr"] = reti["inpaddr"]
        ret["srvid_out_addr"] = reti["outpaddr"]
        ret["srvid_in_addr_onion"] = reti["inpaddr_onion"] 
        ret["srvid_out_addr_onion"] = reti["outpaddr_onion"]
        reti = self.i2p_bob_i.dumpi2p_bob() 
        ret["i2p"] = reti
        str = binascii.b2a_base64(json.dumps(ret))
        return str

    def save(self,path):
        str = self.dump()
        fp = open(path, 'wb')
        fp.write(str)
        fp.close()

    def load(self,path):
        fp = open(path, 'rb')
        str = fp.read()
        fp.close()
        return loads(str)

    def loads(self,str):
        str = binascii.a2b_base64(str)
        ret = json.loads(str)
        self.srvid = ret["srvid"]
        self.srvid_in = ret["srvid_in"]
        self.srvid_out = ret["srvid_out"]
        self.srvid_in_pkey = ret["srvid_in_pkey"]
        self.srvid_out_pkey = ret["srvid_out_pkey"]
        self.srvid_in_addr = ret["srvid_in_addr"]
        self.srvid_out_addr = ret["srvid_out_addr"]
        self.srvid_in_addr_onion = ret["srvid_in_addr_onion"]
        self.srvid_out_addr_onion = ret["srvid_out_addr_onion"]
        self.port = ret["port"]
        self.port_range_faktor = ret["port_range_faktor"]
        self.i2p_host = ret["i2p_host"]
        self.i2p_port = ret["i2p_port"]
        self.i2p_bob_i = i2p_bob(self.i2p_host,self.i2p_port,'0.0.0.0', '0.0.0.0', self.port + self.port_range_faktor, self.port, self.srvid_in, self.srvid_out)
        reti = self.i2p_bob_i.loadsi2p_bob(ret["i2p"])
        self.i2p_bob_i.seti2p_bob(reti)
        self.start()        

    def reload(self):
        self.i2p_bob_i.load()
        self.i2p_bob_i.stop()
        self.i2p_bob_i.start()

    def start(self):
        self.i2p_bob_i.load()
        self.i2p_bob_i.start()

    def stop(self): 
        self.i2p_bob_i.stop()


def FakeI2PTor_loads(str):
    try:
        str = binascii.a2b_base64(str)
        ret = json.loads(str)
        re = ret["i2p"]
        re = binascii.a2b_base64(re)
        re = json.loads(re)
        ret["i2p"] = re
    except:
        ret = {}
        ret["i2p"] = {}
        r = ret
        ret = r["i2p"]
        ret["started"] = False
        ret["i2p_host"] = ''
        ret["i2p_port"] = 0
        ret["inhost"] = ''
        ret["outhost"] = ''
        ret["inport"] = 0
        ret["outport"] = 0
        ret["insrvid"] = ''
        ret["outsrvid"] = ''
        ret["outpkey"] = ''
        ret["inpkey"] = ''
        ret["quiet_in"] = False
        ret["quiet_out"] = False
        ret["in_is_out"] = False
        ret["outpaddr"] = ''
        ret["inpaddr"] = ''
        ret["outpaddr_onion"] = ''
        ret["inpaddr_onion"] = ''
       
        r["i2p"] = ret
        ret = r
        ret["srvid"] = ''
        ret["srvid_in"] = ''
        ret["srvid_out"] = ''
        ret["srvid_in_pkey"] = ''
        ret["srvid_out_pkey"] = ''
        ret["srvid_in_addr"] = ''
        ret["srvid_out_addr"] = ''
        ret["srvid_in_addr_onion"] = ''
        ret["srvid_out_addr_onion"] = ''

        ret["port"] = 0
        ret["port_range_faktor"] = 0
        ret["i2p_host"] = ''
        ret["i2p_port"] = ''
    return ret

class Client_Thread:
	def __init__(self, c_socket, addr, cf, i2p_host, i2p_port, port_range_faktor, i2p_http_proxy_host, i2p_http_proxy_port, i2p_http_proxy_nonce, lock, debug=False):
		RECV_BUFSIZE = 1024  # maximum amount of data to be received
		self.debug = debug
		self.c_socket = c_socket
		self.c_socket_str = '%s:%d' % (addr[0],addr[1])
		self.c_socket.send('Welcome to the server.\n'.encode())
                self.i2p_host = i2p_host
                self.i2p_port = i2p_port
                self.i2p_http_proxy_host = i2p_http_proxy_host
                self.i2p_http_proxy_port = i2p_http_proxy_port
                self.i2p_http_proxy_nonce = i2p_http_proxy_nonce
                self.lock = lock
                self.onion = {}
                self.onion_provider = {}
                self.onions = []
                self.cf=cf
                self.port_range_faktor = port_range_faktor
                self.authenticate = False
                self.scf=(b'250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="%s.i2p.auth"\r\n' % self.cf)
		self._print_debug('connected')
                self.lt()
                if not os.path.isfile((b'%s.i2p.auth' % self.cf)):
                   state = self.dump()
                   self.save_state((b'%s.i2p' % self.cf), state)
                   self.save_md5_state((b'%s.i2p.auth' % self.cf), state)
                self.ut()
		# main loop: receive/send data
		while True:
			data = self.c_socket.recv(RECV_BUFSIZE)
			if not data:
				break
			self._do_stuff(data)
		self.c_socket.close()
		self._print_debug('disconnected')
       
        def lt(self):
           try:
              self.lock.acquire()
           except:
              return

        def ut(self):
           try:
              self.lock.release()
           except:
              return 
          
        def file_string(self):
           fp = open(('%s.i2p' % self.cf), 'rb')
           nr = fp.read()
           return nr

        def md5_file(self):
           nr = self.file_string()
           return md5(nr)

        def loads_md5(self):
            nr = self.dump()
            nr  = md5(nr)
            return nr
     
        def save_md5(self,path):
            nr = self.loads_md5()
            fp = open(path,'wb')
            fp.write(nr)
            fp.close()

        def save_md5_state(self,path,state):
            nr = md5(state)
            fp = open(path,'wb')
            fp.write(nr)
            fp.close()

        def save_md5_ex(self,path):
            nr = self.file_string()
            nr = md5(nr)
            fp = open(path,'wb')
            fp.write(nr)
            fp.close()

	# play with received data
	def _do_stuff(self, data):
                data = Replacer(data,'\r\n','')
                data = Replacer(data,'\n','')
                if data.startswith(b'PROTOCOLINFO'):
                   self.c_socket.send(b'250-PROTOCOLINFO 1\r\n')
                   self.c_socket.send(self.scf)
                   self.c_socket.send(b'250-VERSION Tor="0.2.7.5"\r\n')
                   self.c_socket.send(b'250 OK\r\n')
                elif data.startswith(b'AUTHENTICATE '):
                      if self.authenticate:
                         self.c_socket.send(b'250 OK\r\n')
                         return
                      self.lt()
                      nr = self.file_string()
                      self.ut()
                      nrc = md5(nr)
                      f = data.split()
                      if len(f) == 2: 
                          try:
                             f = binascii.a2b_hex(f[1])
                             if f == nrc:   
                                self.c_socket.send(b'250 OK\r\n') 
                                ret = self.loads(nr)
                                self.loads_onion(ret)
                                self.onions = []
                                self.authenticate = True
                                for k in self.onion:
                                    v = self.onion[k]
                                    n = FakeI2PTor()
                                    n.loads(v)
                                    self.onions.append(n)
                                    if(len(v) > 5):
                                       self.port_range_faktor = self.port_range_faktor + 1
                             else:
                                self.c_socket.send(b'515 Authentication failed: Wrong length on authentication cookie.\r\n')
                                self.c_socket.close()
                          except:
                              self.c_socket.send(b'515 Authentication failed: Wrong length on authentication cookie.\r\n')
                              self.c_socket.close()
                      else:
                           self.c_socket.send(b'515 Authentication failed: Wrong length on authentication cookie.\r\n')
                           self.c_socket.close()   
                elif data.startswith(b'GETINFO version'):
                   self.c_socket.send(b'250-version=0.2.7.5\r\n')
                   self.c_socket.send(b'250 OK\r\n')
                elif data.startswith(b'SIGNAL NEWNYM'):
                   if not self.authenticate:
                      self.c_socket.send(b'514 Authentication required\r\n')
                      self.c_socket.close()
                      return 
                   self.c_socket.send(b'250 OK\r\n')
                   self.onion = {}
                   self.onion_provider = {}
                   for s in self.onions:
                       s.reload()
                       f = s.getSrvId()
                       p = s.getPrivKey()
                       g = s.getSrvIdAddrOnion() 
                       self.onion[(b'%s' % f)] = p
                       self.onion_provider[(b'%s' % g)] = f
                   self.lt()
                   state = self.dump()
                   self.save_state((b'%s.i2p' % self.cf),state)
                   self.save_md5_state((b'%s.i2p.auth' % self.cf),state)
                   self.ut()
                elif data.startswith(b'ADD_ONION NEW:BEST port='):
                       if not self.authenticate:
                         self.c_socket.send(b'514 Authentication required\r\n')
                         self.c_socket.close()
                         return 
                       f = data.split(b'ADD_ONION NEW:BEST port=')
                       if len(f) == 2:  
                          fport = f[1] 
                          fport = int(fport)
                       fitor = FakeI2PTor(fport,self.i2p_host,self.i2p_port,0)
                       fitor.start()
                       srvid = fitor.getSrvId()
                       pkey = fitor.getPrivKey()
                       pkey_i2p = fitor.getSrvIdPkey()
                       addr_onion = fitor.getSrvIdAddrOnion()
                       self.c_socket.send((b'250-ServiceID=%s\r\n' % addr_onion))
                       self.c_socket.send((b'250-PrivateKey=BEST:%s\r\n' % pkey_i2p))
                       self.c_socket.send(b'250 OK\r\n')
                       self.onion[srvid] = pkey
                       self.onion_provider[addr_onion] = srvid
                       http_request_proxy_add_thread(addr_onion,pkey_i2p,self.i2p_http_proxy_host, self.i2p_http_proxy_port, self.i2p_http_proxy_nonce)
                       lf = len(srvid)
                       print(lf)
                       self.lt()
                       state = self.dump()
                       self.save_state((b'%s.i2p' % self.cf),state)
                       self.save_md5_state((b'%s.i2p.auth' % self.cf),state)
                       self.ut()
                       self.onions.append(fitor)
                elif data.startswith(b'ADD_ONION NEW:RSA1024 port='):
                   if not self.authenticate:
                      self.c_socket.send(b'514 Authentication required\r\n')
                      self.c_socket.close()
                      return
                   f = data.split(b'ADD_ONION NEW:RSA1024 port=')
                   if len(f) == 2:
                        fport = f[1]
                        fport = int(fport)
                   fitor = FakeI2PTor(fport,self.i2p_host,self.i2p_port,self.port_range_faktor)
                   fitor.start()
                   srvid = fitor.getSrvId()
                   pkey = fitor.getPrivKey()  
                   pkey_i2p = fitor.getSrvIdPkey()
                   addr_onion = fitor.getSrvIdAddrOnion()
                   self.c_socket.send((b'250-ServiceID=%s\r\n' % addr_onion))
                   self.c_socket.send((b'250-PrivateKey=RSA1024:%s\r\n' % pkey_i2p))
                   self.c_socket.send(b'250 OK\r\n')
                   self.onion[srvid] = pkey
                   self.onion_provider[addr_onion] = srvid
                   http_request_proxy_add_thread(addr_onion,pkey_i2p,self.i2p_http_proxy_host, self.i2p_http_proxy_port, self.i2p_http_proxy_nonce)
                   lf = len(f)
                   self.lt()
                   state = self.dump()
                   self.save_state((b'%s.i2p' % self.cf),state)
                   self.save_md5_state((b'%s.i2p.auth' % self.cf),state)
                   self.ut()
                   self.onions.append(fitor)
                   self.port_range_faktor = self.port_range_faktor + 1
                elif data.startswith(b'DEL_ONION '):
                   if not self.authenticate:
                      self.c_socket.send(b'514 Authentication required\r\n')
                      self.c_socket.close()
                      return
                   f = data.split()
                   i = 0
                   if len(f) == 2:
                       f = f[1]
                       lf = len(f)
                       if not (lf > 0):
                           self.c_socket.send(b'512 Malformed Onion Service id\r\n')
                           self.c_socket.close()
                           return
                       if ((not (f in self.onion)) and (not (f in self.onion_provider))):
                          self.c_socket.send(b'552 Unknown Onion Service id\r\n')
                          self.c_socket.close()
                          return
                       self.c_socket.send(b'250 OK\r\n')
                       found = False
                       o = b''
                       for s in self.onions:
                           if s.getSrvIdAddrOnion() == f:
                              f = s.getSrvId()
                              o = s.getSrvIdAddrOnion()
                              found = True
                           elif s.getSrvId() == f:
                              found = True
                              o = s.getSrvIdAddrOnion()
                           else:
                              continue

                           if found:
                              s.stop()
                              del self.onion[(b'%s' % f)]
                              del self.onion_provider[(b'%s' % o)]
                              self.lt()
                              state = self.dump()
                              self.save_state((b'%s.i2p' % self.cf),state)
                              self.save_md5_state((b'%s.i2p.auth' % self.cf),state)
                              self.ut()
                              del s
                              if lf > 5:
                                 self.port_range_faktor = self.port_range_faktor - 1
                              break
                   else:
                       self.c_socket.send(b'512 Malformed Onion Service id\r\n')
                       self.c_socket.close()
                       return
                else:
                   #self.c_socket.sendall(data)
                   self.c_socket.close()

	def _print(self, s):
		print('[Client] %s> %s' % (self.c_socket_str, s))


	def _print_debug(self, s):
		if self.debug: self._print(s)

        def dump(self):
            uret = {}
            uret["onion"] = self.onion
            uret["onion_provider"] = self.onion_provider 
            ret = uret
            str = binascii.b2a_base64(json.dumps(ret))
            return str

        def save_state(self,path,state):
            str = state
            fp = open(path, 'wb')
            fp.write(str)
            fp.close()

        def save(self,path): 
            str = self.dump()    
            fp = open(path, 'wb')
            fp.write(str)
            fp.close()

        def loads(self,fonion):
            str = binascii.a2b_base64(fonion)
            ret = json.loads(str)
            ret = utoba(ret)
            return ret

        def loads_onion(self,ret):
            self.onion = ret["onion"]
            self.onion_provider = ret["onion_provider"]

        def load(self,path):
            fp = open(path, 'rb')
            str = fp.read()
            fp.close()
            ret = self.loads(str)    
            self.onion = ret

class Socket_Server:
	def __init__(self, host='', port=1234, i2p_host='127.0.0.1', i2p_port=2827, cf="/myservices/tor/control_auth_cookie", port_range_faktor=10, i2p_http_proxy_host='127.0.0.1', i2p_http_proxy_port=4444, i2p_http_proxy_nonce='', ssh=False, debug=False):
		self.host = host # '' for all available interfaces
		self.port = port
		self.cf = cf
                self.i2p_host = i2p_host
                self.i2p_port = i2p_port
                self.i2p_http_proxy_host = i2p_http_proxy_host
                self.i2p_http_proxy_port = i2p_http_proxy_port
                self.i2p_http_proxy_nonce = i2p_http_proxy_nonce
                self.port_range_faktor = port_range_faktor
                self.ssh = ssh
		self.debug = debug
		listen_backlog = 10  # must be set; only optional in Python >= v3.5

		# create socket
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._print_debug('Socket created')

		# bind socket to address
		try:
			self.socket.bind((self.host, self.port))
			self._print_debug('Socket bind complete')
		except socket.error as msg:
			self._print('Bind failed: %s' % (msg))
			exit(1)

		# accept connections
		self.socket.listen(listen_backlog)  # listen_backlog optional in >= v3.5
		self._print('Socket now listening on port %d' % self.port)

                if not self.ssh:
		    # set signal handler
		    signal.signal(signal.SIGINT, self._shutdown_handler)   # KeyboardInterrupt
		    signal.signal(signal.SIGTERM, self._shutdown_handler)  # kill

                self.lock = threading.RLock()

		# main loop to accept connections
		while 1:
			try:
				c_socket, addr = self.socket.accept()
			except (KeyboardInterrupt, InterruptedError):
				break

			thread = threading.Thread(target=Client_Thread, args=(c_socket, addr, self.cf, self.i2p_host, self.i2p_port, self.port_range_faktor, self.i2p_http_proxy_host, self.i2p_http_proxy_port, self.i2p_http_proxy_nonce, self.lock, self.debug))
			thread.setDaemon(True)
			thread.start()

			self._print_debug('Active clients: %d' % self.get_active_client_connections())

	# return number of thread without main thread ^= connections
	def get_active_client_connections(self):
		return threading.active_count() - 1

	# close socket on shutdown
	def shutdown(self):
		self.socket.close()
		self._print('Gracefull shutdown. Bye.')

	def _shutdown_handler(self, signum, frame):
		self.shutdown()

	def _print(self, s):
		print('[SERVER] %s' % s)

	def _print_debug(self, s):
		if self.debug: self._print(s)

def i2p_test():
    i2p_b = i2p_bob()
    i2p_b.loadi2p_bob('i2p_bob.txt')
    i2p_b.load()
    i2p_b.start()
    i2p_b.savei2p_bob('i2p_bob.txt')
    ret = i2p_b.geti2p_bob()
    print(ret["outpkey"])
    #i2p_b.stop()

def load_settings():
    fp = open('settings.json', 'rb')
    ret = fp.read()
    ret = json.loads(ret)
    fp.close()
    return ret

def save_settings(ret):
    fp = open('settings.json', 'wb')
    js = json.dumps(ret,4)
    if ret["debug"]:
       debug_string = "true"
    else: 
       debug_string = "false"
    out = (b'{"cookiefile_path": "%s", "server_host": "%s", "server_port": %s, "i2p_host": "%s", "i2p_port": %s, "port_range_faktor": %s, "i2p_http_proxy_host": "%s","i2p_http_proxy_port": %s, "i2p_http_proxy_nonce": "%s","debug": %s}' % (ret["cookiefile_path"],ret["server_host"],ret["server_port"],ret["i2p_host"],ret["i2p_port"],ret["port_range_faktor"],ret["i2p_http_proxy_host"],ret["i2p_http_proxy_port"],ret["i2p_http_proxy_nonce"],debug_string))
    js = out
    fp.write(js)
    fp.close()

def current_dir():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return dir_path

def create_settings():
    if os.path.isfile('settings.json'):
       return
    ret = {}
    ret["cookiefile_path"] = "/myservices/tor/control_auth_cookie"
    ret["server_port"] = 1234
    ret["server_host"] = ''
    ret["i2p_host"] = "127.0.0.1"
    ret["i2p_port"] = 2827
    ret["port_range_faktor"] = 10
    ret["i2p_http_proxy_host"] = "127.0.0.1"
    ret["i2p_http_proxy_port"] = 4444
    ret["i2p_http_proxy_nonce"] = "3"
    ret["debug"] = True
    fp = open('settings.json', 'wb')
    if ret["debug"]:
       debug_string = "true"
    else:
       debug_string = "false"
    out = (b'{"cookiefile_path": "%s", "server_host": "%s", "server_port": %s, "i2p_host": "%s", "i2p_port": %s, "port_range_faktor": %s, "i2p_http_proxy_host": "%s", "i2p_http_proxy_port": %s, "i2p_http_proxy_nonce": "%s", "debug": %s}' % (ret["cookiefile_path"],ret["server_host"],ret["server_port"],ret["i2p_host"],ret["i2p_port"],ret["port_range_faktor"],ret["i2p_http_proxy_host"],ret["i2p_http_proxy_port"],ret["i2p_http_proxy_nonce"],debug_string))
    #js = json.dumps(ret,4)
    js = out
    fp.write(js)
    fp.close()

def startI2PHelperMain(set_signal_handler=False,second=False):
    print set_signal_handler
    http_request_nonce()
    #i2p_test()
    create_settings()
    ret = load_settings()
    ret["i2p_http_proxy_nonce"] = http_request_nonce(host=utobs(ret["i2p_http_proxy_host"]), port=ret["i2p_http_proxy_port"], nonce=utobs(ret["i2p_http_proxy_nonce"]))
    settings = ret
    # Add Here new settings
    #ret["debug"] = True  
    save_settings(ret)
    if ret["i2p_http_proxy_nonce"] == "3" or ret["i2p_http_proxy_nonce"] == b'3':
       print "try again!"
    else:
       server = Socket_Server(host=utobs(ret["server_host"]),port=ret["server_port"],cf=utobs(ret["cookiefile_path"]),i2p_host=utobs(ret["i2p_host"]),i2p_port=ret["i2p_port"],port_range_faktor=ret["port_range_faktor"],i2p_http_proxy_host=utobs(ret["i2p_http_proxy_host"]),i2p_http_proxy_port=ret["i2p_http_proxy_port"],i2p_http_proxy_nonce=ret["i2p_http_proxy_nonce"],ssh=set_signal_handler,debug=ret["debug"])

if __name__ == "__main__":
   startI2PHelperMain()

