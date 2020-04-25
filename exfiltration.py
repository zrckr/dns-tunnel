#!/usr/bin/env python3
# coding: utf-8

import io
import os
import base64
import random
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
__pad = lambda s, bs: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
__unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def aes_encrypt(raw, key):
    key = hashlib.sha256(key).digest()
    raw = __pad(raw.decode(), AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return key, iv + cipher.encrypt(raw.encode())

def aes_decrypt(enc, key):
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return __unpad(cipher.decrypt(enc[AES.block_size:]))

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

#------------------------------------------------------------------------
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

def first_decode(header):
    def_name, def_args = header.decode().split('$')
    def_args = bytearray.fromhex(def_args)

    if def_name == 'aes_encrypt':
        return globals()['aes_decrypt'], def_args
    else:
        return globals()['scramble'], tuple(def_args), True
#------------------------------------------------------------------------

# data = b'Hello, world!'
# key = random_bytes(32)

# enc = domain_encode(data, 'google.com', base64.urlsafe_b64encode, scramble, (3, 11))
# enc = domain_encode(data, 'google.com', base64.urlsafe_b64encode, aes_encrypt, key)

# func, *args = domain_decode(str(enc[0]), base64.urlsafe_b64decode, first_decode)
# for label in enc[1:]:
#     key, dec = domain_decode(str(label), base64.urlsafe_b64decode, func, *args)

# assert data == dec