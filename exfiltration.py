#!/usr/bin/env python3
# coding: utf-8

import io
import os
import base64
import random
import socket
import hashlib
import binascii
import dnslib as dns

from bitstring import BitArray
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SOCK_BUFFER_SIZE    = 1024
MAX_DNS_LEN         = 512
HALF_DNS_LEN        = 255
MAX_DOMAIN_LEN      = 255
MAX_LABEL_LEN       = 63
MAX_RAW_DATA_LEN    = 140
MAX_ENC_DATA_LEN    = 104

#------------------------------------------------------------------------
def check_bit(data, index):
    d = BitArray(data)
    return True if d[index] else False

#------------------------------------------------------------------------
def aes_encrypt(raw, key) -> bytes:
    key = hashlib.sha256(key.encode()).digest()
    iv = Random.new().read(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(raw, 16))

def aes_decrypt(enc, key) -> bytes:
    key = hashlib.sha256(key.encode()).digest()
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]), 16)

def pad_bytes(data, block_size):
    return pad(data, block_size)

def unpad_bytes(data, block_size):
    return unpad(data,block_size)

#------------------------------------------------------------------------
def scramble(data, offset, reverse=False) -> bytes:
    """ 
        Scrambles/descrambles bytes with specified offset
    """
    a = BitArray(data, endian="little")
    b = BitArray(length=len(a))
    
    if len(offset) != 2:
        raise ValueError("The offset must be a tuple with two values!")
    p1, p2 = offset

    if p1 >= p2:
        raise ValueError("The first index must be less than the second index!")

    for i in range(len(a)): 
        if (i < p1):
            b[i] = a[i]
        elif (i < p2):
            x = (a[i-p1] if reverse else b[i-p1])
            b[i] = a[i] ^ x
        else:
            x = (a[i-p1] if reverse else b[i-p1])
            y = (a[i-p2] if reverse else b[i-p2 ])
            b[i] = a[i] ^ x ^ y

    return b.tobytes()

#------------------------------------------------------------------------
def random_bytes(n) -> bytearray:
    """ Generates random bytearray with n-length """
    return bytearray(os.urandom(n))

def chunk(data, chunk_size) -> list:
    """ Splits data into equal-sized chunks """
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

#------------------------------------------------------------------------
def domain_encode(data, domain, base_encoding) -> dns.DNSLabel:
    """ 
        Encodes data to DNS domain name (RFC 1035).
        Returns encoded DNSLabel with encapsulated data.
    """
    labels = [i.encode('idna') for i in domain.split('.')]

    data = base_encoding(data)
    chucked_data = chunk(data, 63)

    try:
        result = dns.DNSLabel(chucked_data + labels)
        return result
    except Exception:
        print("Original data length must be less than 141 bytes!")
   

def domain_decode(domain, base_decoding) -> bytes:
    """ 
        Decodes data from DNS domain name and returns bytes.
    """
    parts = domain.split(".")
    data = ''.join(parts[:-3]).encode()
    raw = base_decoding(data)

    return raw

#------------------------------------------------------------------------
def ip_encode(data, ipv6) -> list:
    """ 
        Encodes data to AAAA or A rdata types.
        Returns list of RDATA objects with encapsulated data.
    """
    chunk_size = 16 if ipv6 else 4
    data = pad_bytes(data, chunk_size)

    if (len(data) > chunk_size):
        data = chunk(data, chunk_size)
    else:
        data = [data]

    if (ipv6):
        qdata = [dns.AAAA(socket.inet_ntop(socket.AF_INET6, i)) for i in data]
    else:
        qdata = [dns.A(socket.inet_ntop(socket.AF_INET, i)) for i in data]

    return qdata

def ip_decode(records) -> bytes:
    """ 
        Decodes data from AAAA or A records (from IPv6 or IPv4 addresses)
        resource record and returns bytes.
    """
    raw = b''

    for record in records:
        if (len(record.rdata.data) > 4):
            raw += socket.inet_pton(socket.AF_INET6, str(record.rdata))
        else:
            raw += socket.inet_pton(socket.AF_INET, str(record.rdata))
    
    if (len(record.rdata.data) > 4):
        return unpad_bytes(raw, 16)
    else:
        return unpad_bytes(raw, 4)

#------------------------------------------------------------------------