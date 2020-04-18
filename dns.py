#!/usr/bin/env python3
# coding: utf-8

import os
import base64
import dnslib
import random
import struct
import binascii
from bitstring import BitArray

BUFFER_SIZE = 1024
BIG_DNS = 512
DNS_DOMAIN_LEN = 255
DNS_LABEL_LEN = 63

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

    if len(data) + len(domain) + 1 > DNS_DOMAIN_LEN:
        raise ValueError("The data size greater than 255 bytes!")
    
    if (crypt):
        data = crypt(data)

    parts = [data]
    if len(data) > DNS_LABEL_LEN:
        parts = [data[i:i+DNS_LABEL_LEN] for i in range(0, len(data), DNS_LABEL_LEN)]

    string = ""
    for frag in parts:
        string += str(base_encoding(frag), 'utf-8') + "."
    string += domain

    if len(string) > DNS_DOMAIN_LEN:
        raise ValueError("The result string's length greater than 255 bytes!")

    return string

def decode_from_domain(domain, base_decoding, decrypt=None):
    """ Decode data from DNS domain name"""
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

def dns_to_q(data, domain, qtype):
    data_msg = encode_to_domain(data, domain, base64.urlsafe_b64encode)
    d_question = dnslib.DNSRecord.question(data_msg, qtype)

    return d_question.pack()

def dns_proc_q(raw_question):
    d_question = dnslib.DNSRecord.parse(raw_question)
    d_qname = str(d_question.q.get_qname())
    d_data = decode_from_domain(d_qname, base64.urlsafe_b64decode)

    d_answer = d_question.reply()
    d_rr = dnslib.RR(d_qname, rtype=16, rdata=dnslib.TXT(d_data))
    d_answer.add_answer(d_rr)
    
    print(d_answer, end="\n\n")
    return d_answer.pack()

def dns_from_q(raw_answer):
    d_answer = dnslib.DNSRecord.parse(raw_answer)

    data = b''
    for rr in d_answer.rr:
        data += rr.rdata.data[0]
    return data

# def exf_file_rr(filename, domain, buffer_size=32):
#     requests = []
#     with open(filename, 'rb') as file:
#         data = file.read(buffer_size)
#         part = 0
        
#         while (data):
#             payload = struct.pack(f'L{buffer_size}s', part, data)
#             domain_payload = encode_to_domain(data, domain, base64.b64encode)
#             requests += [dnslib.DNSRecord.question(domain_payload)]
            
#             data = file.read(buffer_size)
#             part += 1
    
#     return requests