import binascii
import sys
import hashlib
import base64
import json

def md5(N):
    m = hashlib.md5()
    m.update(N)
    return m.hexdigest()

def keys():
    fp = open("./keys", "rb")
    k = fp.read()
    fp.close()
    k = base64.b64decode(k)
    js = json.loads(k)
    js = utoba(js)
    return js

def keys_saves(keys):
    fp = open("./keys", "wb")
    fp.write(base64.b64encode(json.dumps(keys)))
    fp.close()


def b64to32_address(key):
    raw_key = base64.b64decode(key, '-~')
    hash = hashlib.sha256(raw_key)
    base32_hash = base64.b32encode(hash.digest())
    return (b'%s.b32.i2p' % base32_hash.lower().replace('=', ''))

def utoba(t):
    l = []
    for k in t:
        l.append(k.encode())
    return l

if __name__ == "__main__":
   fp = open("/myservices/tor/control_auth_cookie.i2p", "rb")
   ret = fp.read()
   fp.close()
   fp = open("/myservices/tor/control_auth_cookie.i2p.auth", "rb")
   ret2 = fp.read()
   fp.close()
   fp = open("/myservices/tor/control_auth_cookie", "rb")
   ret3 = fp.read()
   fp.close()
   m = md5(ret)
   k = [b'vWZvi8aDqVeKmFUyNVZy2G8iuWdm93OunX15ScMn0yCy6qLf0tlTH3HcTBa4EB9dr6ioiyGD1dluRARdHEYNkXdq1zN-CGumhmVVORejQbH-7wiIl5uxyyKt9OtQpjRzQm~3Dn~Q4F0Cqxb2A1aHOpoc84CKfAX0WRiPsc3rQUlvlS7c-ScuzNZsVKk1MV6Jyctg6tPqQ1w2NyCESYD2OKjCyp7k-8HL5wBQbENDpQBzHI3-IfKTcsLdTZKH82voGO~JNi5uSv5-~CjxfDKmmhw~X6OmTcHA42HxK~7yzkCA324ETIlRFyRAhF1QDq32KsT1XtMEANRk1UlJ7A~x3ieZBmSKzJX180d988pXg-8yX~EGUuAS6P1tsvpw4te9E0Wo6bp3FpUGQTeXm41SXWAbhQCs41EGvEoK5kDx225Bm7q9oyss7en3o2-lciRmzkFOgnEt7NGH6k18hkDs8s9N9Dc74pmPZeSaDD89gesjG21gy82ltCAHSjUqZnkKAAAAnfJP1WlPMTLjTykw46~RccgRJKY9YQFM9di0wOR8oa~IWOTb9yAH7U-mseGhMJPvgJUkCwZktCdSWTdrxnwA17LiRrmK7IfALE6843W8pDteg11AG4BtI37VAPVbff3fcl~gMyJJJw6oAMC80cLJ1oqfB8395KabDuanQkZFInKxsJL-39pgSvCEjZBbjf7TVpoZ2VLGzzpadHilzOo8SQt6S6Z~So1K678qNf~PvnPl8TshgJ6mTvVlbOqOPVFBL1IzYMElsKOUOoNC5JYOXyH8n9QWc7dejWFT~GDblgMOpLDZpKpHO5gPJ68fmFcLrp1~3nYiNwYS2RlDTzYnuDerVwaMsRLr3p1uuQlu3PORnglO', b'-jnJJn1yR0F-acYICeatROg2y8Pkrjzq1ox3j33xhc9lOOgl73QibwmIWWmXUr03-Xz81cKNYYRiRmd3uglgxFhOO5cDw88XsaKigLdzK4yIwWiTPcQCBakYXe414~2lCZKHeKLbi2WumEP3CWYqC-yFP2nrPHwIsLR~38OnqQ1qduvpsc3dIGFyjFv82XkhPVdfpGn3wnkLg2GWzDDhZkG7NjZVsDlbIveByYk8cFbxBstulLYA~6vxtPnGKAmx5Sz~8wcPgwuIUwKDBZ29oevea3kVDdF8tKtUyavBiXDQuZpz-uHW6xEtXVCkrTsDyECQztvXGyZBWOPGUf5hITt~rd1i~peSV-sslDVgmHNl5PcbapkhudRwQ08bsDE6V~urMbeKIJy9L0CqTBtgADg1~FdMWS5yAew-lTDM-mhRdwRr67qTWiTnYJaWOF-GPacLWs10VgMgR2fvnC-hk9ym-GQheMgfRQ8~Jueck5SZl3VfIuE-BX~pDAeVjs-GAAAAYppsSFxipiubV5zP1UTOi9wVdlBsFD1o7xKpUHSD~2Z7z6NrBnkpTpDRAxBmpWoVJCeAmnFhaCq5Q~YRqDZQK5kRO8-pAr~FD0s-~lDYMxrFlPDcPzdwFQZOlJ5oshJwfTDuAe~J5hr2utqOaeqgD8LJk9eZhom2Dk~OXqituqIj7bOAIucnDMMs8z9AQ-fISd1oAooWyJIz-N4Qci5FuqGSFAGoZdCxpYBDBE7Cb0eY1xQt7BNJQjzncPaY3iH~2Or9KJsEFxbi1MuDaMnnZwlEZcC7eCF384W-AVlff7j7~77Pl0YaMdVcpFBC9tNMWxb0cYTwWYxWyYyWxEdjlCeiFr-xnu1-JlBZmVI2aMCzL~9A']
   keys_saves(k)
   k = keys()
   for nn in (1,2,3):
      print nn
   print k
   print binascii.b2a_hex(m)
   print binascii.b2a_hex(ret2)
   print binascii.b2a_hex(ret3)
   for ke in k: 
       print(b64to32_address(ke))
    
