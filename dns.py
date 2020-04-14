#!/usr/bin/env python3
# coding: utf-8

import os
import base64
import dnslib
import binascii
from bitstring import BitArray

BUFFER_SIZE = 1024
MAX_DOMAIN_LEN = 255
MAX_LABEL_LEN = 63

def scramble(data, offset, reverse=False):
    """ Scramble/descramble bytes with specified offset """
    
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

def random_bytes(n):
    """ Generate random bytearray with n-length """
    return bytearray(os.urandom(n))


def encode_to_domain(data, domain, base_encoding, crypt=None):
    """ Encode data to DNS domain name (RFC 1035) """

    if len(data) + len(domain) + 1 > MAX_DOMAIN_LEN:
        raise ValueError("The data size greater than 255 bytes!")
    
    if (crypt):
        data = crypt(data)

    parts = None
    if len(data) > MAX_LABEL_LEN:
        parts = [data[i:i+MAX_LABEL_LEN] for i in range(0, len(data), MAX_LABEL_LEN)]

    string = ""
    for frag in parts:
        string += str(base_encoding(frag), 'ascii') + "."
    string += domain

    if len(string) > MAX_DOMAIN_LEN:
        raise ValueError("The result string's length greater than 255 bytes!")

    return string

def decode_from_domain(fake_domain, base_decoding, decrypt=None):
    """ Decode data from DNS domain name"""
    parts = fake_domain.split(".")
    data = b''

    # Look for the presence of encoded bytes...
    try:
        for i in parts:
            msg_bytes = i.encode('ascii')
            data += base_decoding(msg_bytes)
    except Exception as error:
        # Throw and go
        pass

    if (decrypt):
        data = decrypt(data)
    
    return data