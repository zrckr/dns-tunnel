#!/usr/bin/env python3
# coding: utf-8

import io
import os
import base64
import random
import socket
import struct
import hashlib
import binascii
import dnslib as dns

from bitstring import BitArray
from Crypto import Random
from Crypto.Cipher import AES

SOCK_BUFFER_SIZE = 1024

MAX_MSG_LEN    = 512
MAX_DOMAIN_LEN = 255
MAX_LABEL_LEN  = 63

#------------------------------------------------------------------------
__pad__ = lambda s, bs: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
__unpad__ = lambda s: s[:-ord(s[len(s) - 1:])]

def aes_encrypt(raw, key):
    key = hashlib.sha256(key).digest()
    raw = __pad__(raw.hex(), AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return key, iv + cipher.encrypt(raw.encode())

def aes_decrypt(enc, key):
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return __unpad__(cipher.decrypt(enc[AES.block_size:]))

#------------------------------------------------------------------------
def scramble(data, offset, reverse=False):
    """ Scrambles/descrambles bytes with specified offset """
    
    a = BitArray(data, endian="little")
    b = BitArray(length=len(a))
    
    if len(offset) != 2:
        raise ValueError("The offset must be a tuple with two values!")
    p1, p2 = offset

    for i in range(len(a)): 
        if (i < p1):
            b[i] = a[i]
        elif (i < p2 ):
            x = (a[i-p1] if reverse else b[i-p1])
            b[i] = a[i] ^ x
        else:
            x = (a[i-p1] if reverse else b[i-p1])
            y = (a[i-p2] if reverse else b[i-p2 ])
            b[i] = a[i] ^ x ^ y

    return bytearray(offset), b.tobytes()

#------------------------------------------------------------------------
def random_bytes(n):
    """ Generates random bytearray with n-length """
    return bytearray(os.urandom(n))

#------------------------------------------------------------------------
def domain_encode(data, domain, base_encoding, crypt=None, *crypt_args):
    """ 
        Encodes data to DNS domain name (RFC 1035).
        Returns list of DNSLabel objects with encapsulated data.
    """

    labels = [i.encode('idna') for i in domain.split('.')]

    if (crypt): 
        key, data = crypt(data, *crypt_args)

    if len(data) > 32:
        data = [data[i:i+32] for i in range(0, len(data), 32)]
    else:
        data = [data]

    # first = crypt.__name__+ '$' + key.hex()
    # data.insert(0, first.encode())

    result = []
    big_labels = [base_encoding(i) for i in data]

    for label in big_labels:
        result += [dns.DNSLabel([label] + labels)]

    return result

def domain_decode(domain, base_decoding, decrypt=None, *decrypt_args):
    """ 
        Decodes data from DNS domain name and returns bytes.
    """
    parts = domain.split(".")
    data = b''

    # Look for the presence of encoded bytes...
    try:
        for i in parts:
            msg_bytes = i.encode('utf-8')
            data += base_decoding(msg_bytes)
    except Exception as error:
        # Throw and go
        pass

    if (decrypt):
        data = decrypt(data, *decrypt_args)
    
    return data

#------------------------------------------------------------------------
def first_decode(header):
    def_name, def_args = header.decode().split('$')
    def_args = bytearray.fromhex(def_args)

    if def_name == 'aes_encrypt':
        return globals()['aes_decrypt'], def_args
    else:
        return globals()['scramble'], tuple(def_args), True

#------------------------------------------------------------------------
def ip_encode(data, domain, ipv6=False, crypt=None, *crypt_args):
    if (crypt): 
        key, data = crypt(data, *crypt_args)

    data = base64.b32encode(data)
    chunk = 16 if ipv6 else 4

    if (len(data) > chunk):
        data = [data[i:i+chunk] for i in range(0, len(data), chunk)]
    else:
        data = [data]

    if (ipv6):
        qtype = dns.QTYPE.AAAA
        qdata = [dns.AAAA(socket.inet_ntop(socket.AF_INET6, i)) for i in data]
    else:
        qtype = dns.QTYPE.AAAA
        qdata = [dns.A(socket.inet_ntop(socket.AF_INET, i)) for i in data]

    rr = [dns.RR(rname=domain, rtype=qtype, rdata=i, ttl=60) for i in qdata]
    return rr

def ip_decode(records, decrypt=None, *decrypt_args):
    result = b''
    for r in records:
        if (len(r.rdata.data) > 4):
            raw = socket.inet_pton(socket.AF_INET6, str(r.rdata))
        else:
            raw = socket.inet_pton(socket.AF_INET, str(r.rdata))
        result += base64.b32decode(raw)
        
    return result

#------------------------------------------------------------------------