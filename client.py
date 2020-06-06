#!/usr/bin/env python3
# coding: utf-8

import sys
import time
import base64
import random
import select
import socket
import struct
import hashlib
import binascii
import argparse

import dnslib as dns
import exfiltration as exf

class Client():
    def __init__(self, addr, args):
        self.sock = None
        self.addr = addr
        self.timeout = args.timeout
        self.domain = args.domain
        self.qtype = args.qtype.upper()
        self.modes = (args.text, args.rand, args.file)
        self.key = (args.aes_key or args.scramble)
        self.force_tcp = args.force_tcp
    
    def run(self):
        while True:
            try:
                if (self.modes[0]):
                    data = self.read_text()
                elif (self.modes[1]):
                    data = self.read_random()
                    input(f"> Send {len(data)} bytes?")
                elif (self.modes[2]):
                    data = self.read_file()
                
                old_hash = hashlib.sha1(data).digest()

                if (type(self.key) == list):
                    queries = self.dns_ask(data, base64.urlsafe_b64encode, exf.scramble, self.key)
                elif (type(self.key) == str):
                    queries = self.dns_ask(data, base64.urlsafe_b64encode, exf.aes_encrypt, self.key)
                else:
                    queries = self.dns_ask(data, base64.urlsafe_b64encode, None)
                
                answers = []
                for q in queries:
                    if (self.force_tcp):
                        response = self.send_recv(socket.SOCK_STREAM, q)
                    else:
                        response = self.send_recv(socket.SOCK_DGRAM, q)
                    
                    if (exf.check_bit(response, 22)):
                        # TC flag requires for switching to TCP  
                        response = self.send_recv(socket.SOCK_STREAM, q)

                    answers += [response]
               
                new_data = self.dns_extract(answers)
                new_hash = hashlib.sha1(new_data).digest()
                match = new_hash == old_hash

                if (self.modes[0]):
                    print("$", new_data.decode())
                
                elif (self.modes[1]):
                    print("$", new_hash.hex(), match)
                
                elif (self.modes[2]): 
                    with open('downloaded.txt', 'wb') as file:
                        file.write(new_data)
                    print("$", "File downloaded.txt is saved!")
                    break
                
            except (KeyboardInterrupt, SystemExit):
                break
            except Exception as error:
                print("[Info]", str(error))
                break
            except socket.error as error:
                print("[Socket]", str(error))
                break
            except socket.timeout:
                print("[Info]", "Server response timed out! Exiting...")
                break

    def send_recv(self, kind, data=None):
        """
            Sends a binary data over TCP or UDP and waits for response from server.
        """
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(self.timeout)

            if (kind == socket.SOCK_STREAM):
                sock.setblocking(True)
                # DNS message requires additional 2 byte length for TCP 
                dns_length, dns_slice = struct.pack("!H", len(data)), 2
            else:
                dns_length, dns_slice = b'', 0
        
            sock.connect(self.addr)
            if (data):
                sock.send(dns_length + data)

            response = sock.recv(exf.SOCK_BUFFER_SIZE)[dns_slice:]
        
            if not response:
                raise Exception('Error in getting a response!')

        return response

    def read_text(self):
        return input("> ").encode()

    def read_random(self):
        size = random.choice([16, 32, 64, 128])
        return exf.random_bytes(size)

    def read_file(self, buffer=32):
        whole = b''
        with open(self.modes[2], 'rb') as file:
            data = file.read(buffer)
            line = 0

            while (data):
                whole += data.ljust(buffer, b'\0')  
                data = file.read(buffer)
                line += 1

        return whole

    def dns_ask(self, big_data, base_enc, encrypt=None, *args) -> list:
        """
            Generates DNS responses from raw binary data using Base encoding and encryption.
        """
        if encrypt is exf.aes_encrypt:
            data = exf.chunk(big_data, exf.MAX_ENC_DATA_LEN)
        else:
            data = exf.chunk(big_data, exf.MAX_RAW_DATA_LEN)

        if encrypt:
            data = [encrypt(i, *args) for i in data]

        enc_key = ""
        if (args):
            # Encode key (AES or offset) as binary data...
            enc_key = args[0].encode() if isinstance(args[0], str) else bytearray(args[0])
            enc_key = exf.scramble(enc_key, (4, 12))
            enc_key = exf.domain_encode(enc_key, self.domain, base_enc)

        # Generate DNS labels from data 
        labels = [exf.domain_encode(i, self.domain, base_enc) for i in data]
        
        queries = []
        for i in labels:
            if (self.qtype == 'NULL'):
                d = dns.DNSRecord.question(i)
                d.q.qtype = 10
            else:
                d = dns.DNSRecord.question(i, self.qtype)
            
            if (enc_key):
                d.add_question(dns.DNSQuestion(enc_key, dns.QTYPE.TXT))
            queries += [d.pack()]
        
        return queries

    def dns_extract(self, answers):
        """
            Extracts server binary data from series of DNS responses.
        """
        result = b''
        for answer in answers:
            reply = dns.DNSRecord.parse(answer)
            qtype = reply.q.qtype

            raw = b''
            if (qtype == dns.QTYPE.A or qtype == dns.QTYPE.AAAA):
                raw = exf.ip_decode(reply.rr)
            elif (qtype == 10):     # NULL type
                raw = reply.rr[0].rdata.data
            else:
                for rd in reply.rr:
                    if (qtype == dns.QTYPE.TXT):
                        raw += rd.rdata.data[0]
                    else:
                        raw += exf.domain_decode(str(rd.rdata.label), base64.urlsafe_b64decode)
            result += base64.b64decode(raw)
        return result

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="DNS-tunneling project: client script")
    
    parser.add_argument('-c', '--connect', dest='conn', type=str, required=True,
                        help='Establishes a connection to the server at the specified address:port')
    
    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=60,
                        help="Specifies the timeout for server UDP response")
    
    parser.add_argument('-T', '--send-text', dest='text', action='store_true',
                        help='Sends a text string to the server')
    
    parser.add_argument('-F', '--send-file', dest='file', type=str,
                        help='Sends the file to the server. The file path is required.')
    
    parser.add_argument('-R', '--send-random', dest='rand', action='store_true',
                        help='Sends a random byte array to the server')
    
    parser.add_argument('-d', '--domain', dest='domain', type=str, default='example.com',
                        help='Specifies the domain name')
    
    parser.add_argument('-q', '--qtype', dest='qtype', type=str, default="A",
                        help='Specifies the type of record for a DNS question')
    
    parser.add_argument('-s', '--scramble', dest='scramble', type=int, nargs='+',
                        help='Scrambles outgoing traffic passing through the DNS tunnel.\n'+
                            'You need to specify an offset, e.g. (3, 11)')

    parser.add_argument('-a', '--aes', dest='aes_key', type=str,
                        help='Encrypts with AES outgoing traffic passing through the DNS tunnel.\n'+
                            'You need to specify an encryption key')

    parser.add_argument('-S', '--tcp', dest='force_tcp', action='store_true',
                        help='Forcibly sends DNS messages over TCP connection') 

    args = parser.parse_args()
    
    if (args.text and args.file and args.rand) or\
        (not args.text and not args.file and not args.rand) or\
        (args.text and args.file) or\
        (args.text and args.rand) or\
        (args.file and args.rand):
       parser.error('Only or at least one sending mode must be specified!')

    if (args.aes_key and args.scramble):
        parser.error('Only encryption or scrambling must be specified!')

    if (args.scramble and len(args.scramble) > 2):
        parser.error('Only two values must be specified for the offset!')

    if (args.aes_key):
        if (len(args.aes_key) < 3):
            parser.error('AES key is less than 3 characters long!')

    addr = args.conn.split(':')
    client = Client((addr[0], int(addr[1])), args)
    client.run()