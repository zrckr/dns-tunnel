#!/usr/bin/env python3
# coding: utf-8

import io
import os
import random
import socket
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
    raw = __pad__(raw.hex(), AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw.encode())

def aes_decrypt(enc, key):
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return __unpad__(cipher.decrypt(enc[AES.block_size:]))

#------------------------------------------------------------------------
def scramble(data, offset, reverse=False):
    """ 
        Scrambles/descrambles bytes with specified offset
    """
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

    return b.tobytes()

#------------------------------------------------------------------------
def random_bytes(n):
    """ Generates random bytearray with n-length """
    return bytearray(os.urandom(n))

def chunk(data, chunk_size):
    """ Splits data into equal-sized chunks """
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

#------------------------------------------------------------------------
def domain_encode(data, domain, base_encoding, encrypt=None, *crypt_args):
    """ 
        Encodes data to DNS domain name (RFC 1035).
        Returns list of DNSLabel objects with encapsulated data.
    """
    labels = [i.encode('idna') for i in domain.split('.')]

    if len(data) > 32:
        data = chunk(data, 32)
    else:
        data = [data]

    if (encrypt):
        for i in range(len(data)):
            data[i] = encrypt(data[i], *crypt_args)

    result = []
    big_labels = [base_encoding(i) for i in data]

    for label in big_labels:
        result += [dns.DNSLabel([label] + labels)]

    return result

def domain_decode(domain, base_decoding, decrypt=None, *crypt_args):
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
        data = decrypt(data, *crypt_args)

    return data

#------------------------------------------------------------------------
def ip_encode(data, ipv6):
    """ 
        Encodes data to AAAA or A rdata types.
        Returns list of RDATA objects with encapsulated data.
    """
    chunk_size = 16 if ipv6 else 4

    if (len(data) > chunk_size):
        data = chunk(data, chunk_size)
    else:
        data = [data]

    for i in range(len(data)):
        data[i] = data[i].ljust(chunk_size, b'\x00')

    if (ipv6):
        qtype = dns.QTYPE.AAAA
        qdata = [dns.AAAA(socket.inet_ntop(socket.AF_INET6, i)) for i in data]
    else:
        qtype = dns.QTYPE.A
        qdata = [dns.A(socket.inet_ntop(socket.AF_INET, i)) for i in data]

    return qdata

def ip_decode(record):
    """ 
        Decodes data from AAAA or A (from IPv6 or IPv4 addresses)
        resource record and returns bytes.
    """
    raw = b''

    if (len(record.rdata.data) > 4):
        raw += socket.inet_pton(socket.AF_INET6, str(record.rdata))
    else:
        raw += socket.inet_pton(socket.AF_INET, str(record.rdata))

    return raw.rstrip(b'\x00')
#------------------------------------------------------------------------