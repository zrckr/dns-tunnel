#!/usr/bin/env python3
# coding: utf-8

import io
import os
import base64
import random
import struct
import binascii
import dnslib as dns
from bitstring import BitArray

SOCK_BUFFER_SIZE = 1024

MAX_MSG_LEN    = 512
MAX_DOMAIN_LEN = 255
MAX_LABEL_LEN  = 63

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

    return b.tobytes()

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

    if (crypt): data = crypt(data)

    if len(data) > 32:
        data = [data[i:i+32] for i in range(0, len(data), 32)]
    else:
        data = [data]

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
        data = decrypt(data)
    
    return data

#------------------------------------------------------------------------
def dns_process(question):
    parsed = dns.DNSRecord.parse(question)
    
    qname = str(parsed.q.get_qname())
    qtype = parsed.q.qtype
    qdata = getattr(dns, dns.QTYPE.get(qtype))

    data = domain_decode(qname, base64.urlsafe_b64decode)

    answer = parsed.reply()
    d_rr = dns.RR(d_qname, rtype=16, rdata=qdata(data))
    d_answer.add_answer(d_rr)
    
    print(d_answer, end="\n\n")
    return d_answer.pack()