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
import argparse
import textwrap

import dnslib as dns
import exfiltration as exf
from datetime import datetime
from copy import deepcopy

DEBUG = None

def print_with_time(head, message):
        curr_time = datetime.now().strftime("%H:%M:%S.%f")
        print(f"[{head}] [{curr_time[:-3]}]", message)

class Server():
    def __init__(self, host, port, timeout):
        self.addr = (host, port)
        self.hostname = socket.gethostname()
        self.timeout = timeout
        self.sockets = []
        self.tcps = {}

        # Set up UDP and TCP sockets
        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.bind(self.addr)
            self.tcp_sock.setblocking(True)
            self.tcp_sock.listen()
        
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(self.timeout)
            udp_sock.bind(self.addr)

            self.sockets += [self.tcp_sock, udp_sock]

        except socket.error as error:
            print("[Socket] Initialization failed:", str(error))
            return None

    def run(self):
        print(f"[Info] Server is running!")
        while True:
            try:
                # Single-threaded virgin implementation
                readable, writable, exceptional = select.select(self.sockets, [], [], self.timeout)
                now = time.time()
                for sock in readable:
                    if sock.type == socket.SOCK_DGRAM:
                        self.process_udp(sock)
                    
                    if sock.type == socket.SOCK_STREAM:
                        if sock == self.tcp_sock:
                            self.accept_tcp(sock)
                        else:
                            self.process_tcp(sock)

                # closed = []
                # for sock in self.last:
                #     if sock not in self.last and now-self.last[sock] > self.timeout:
                #         sock.close()
                #         closed += [sock]

                # for dead in closed:
                #     del self.last[dead]

                for sock in exceptional:
                    self.sockets.remove(sock)
                    sock.close()

            except ConnectionResetError:
                continue
            except KeyboardInterrupt:
                print("[Interrupt] Exit by the user...")
                break
            except Exception as error:
                print("[Info]", str(error))
                break
            
        print("[Exit] Server is shutting down!")
        for sock in self.sockets:
            sock.close()
        return
 
    def process_udp(self, sock):
        """ 
            Processes UDP connections.
        """
        request, addr = sock.recvfrom(exf.SOCK_BUFFER_SIZE)
        if request:
            print_with_time("UDP", f"Received {len(request)} bytes from {addr}")

            response = self.dns_resolve(request, False)
            sock.sendto(response, addr)
        else:
            return

    def accept_tcp(self, sock):
        """ 
            Accept incoming TCP connection from client for futher transmission.
        """
        c, addr = sock.accept()
        c.settimeout(self.timeout)

        print_with_time("TCP", f"{addr} connected")
        self.sockets += [c]
        self.tcps[c] = addr
        
    def process_tcp(self, sock):
        """ 
            Processes TCP client connection from cache.
        """
        request = sock.recv(exf.SOCK_BUFFER_SIZE)
        if request:
            print_with_time("TCP", f"Receiving {len(request)} bytes from {self.tcps[sock]}")

            # Remove first 2 bytes (DNS length) from TCP payload
            response = self.dns_resolve(request[2:], True)
            # Add first 2 bytes of DNS length for response
            dns_len = struct.pack("!H", len(response))
            
            sock.send(dns_len + response)
        else:
            print_with_time("TCP", f"{self.tcps[sock]} disconnected")

            sock.close()
            self.sockets.remove(sock)
            del self.tcps[sock]

    def dns_resolve(self, query, tcp):
        """ 
            Resolves DNS request from one client at the time.
            Encodes its actual data and forms DNS response from it.
        """
        request = dns.DNSRecord.parse(query)
        reply = request.reply()
        
        # Get actual domain string
        domain = request.q.get_qname()
        # Get QTYPE
        qtype =  request.q.qtype
        # Decode data from domain string
        data = exf.domain_decode(str(domain), base64.urlsafe_b64decode)
        
        # If encryption key is present - decode it for futher data decryption
        if (len(request.questions) > 1):
            enc_domain = str(request.questions[1].get_qname())
            enc_key = exf.domain_decode(enc_domain, base64.urlsafe_b64decode)
            # Descramble key
            enc_key = exf.scramble(enc_key, (4, 12), True)

            # Check if the key is scramble offset
            if len(enc_key) < 3:
                enc_key = tuple(enc_key) 
                data = exf.scramble(data, enc_key, True)
            # Or AES decryption key
            else:
                enc_key = enc_key.decode()
                data = exf.aes_decrypt(data, enc_key)
            # reply.add_question(request.questions[1])

        if DEBUG:
            print_with_time("***", f"DNS QTYPE is {qtype}")
            print_with_time("***", f"Original data length {len(data)} bytes")
            print_with_time("***", f"{data[:24]}...")

        # Encode back extracted data with Base64
        data = base64.b64encode(data)

        # Copy object data to another
        core_domain = deepcopy(domain)
        # Get TLD domain from original object
        core_domain.label = domain.label[-2:]

        if (qtype == dns.QTYPE.A):
            data = exf.ip_encode(data, False)
        
        elif (qtype == dns.QTYPE.AAAA):
            data = exf.ip_encode(data, True)

        elif (qtype ==  dns.QTYPE.TXT):
            data = [dns.TXT(data)]
        
        elif (qtype == 10):
            data = [dns.RD(data)]
        
        else:
            data = exf.domain_encode(data, str(core_domain), base64.urlsafe_b64encode)
            if (qtype == dns.QTYPE.CNAME):
                data = [dns.CNAME(data)]
            elif (qtype ==  dns.QTYPE.MX):
                data = [dns.MX(data)]
            elif (qtype == dns.QTYPE.NS):
                data = [dns.NS(data)]

        for rd in data:
            reply.add_answer(dns.RR(str(domain), rtype=qtype, rdata=rd))
        
        raw_reply = reply.pack()
        # Truncate large (> 512 bytes) data for UDP payload
        if (len(raw_reply) > exf.MAX_DNS_LEN and not tcp):
            print_with_time("DNS", f"Response message is big! Truncate it...")
            reply.header.set_tc(1)
            raw_reply = reply.pack()[:exf.MAX_DNS_LEN]
        
        print_with_time("DNS", f"Sending back the request in size {len(raw_reply)} bytes\n")
        return raw_reply

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":  
    parser = argparse.ArgumentParser(description="DNS-tunneling project: server script")
    
    parser.add_argument('-p', '--port', dest='port', type=int, default=53,
                        help='Specifies the port that the server will listen to')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=10,
                        help='Specifies the timeout for incoming connections')

    args = parser.parse_args()
    DEBUG = args.debug

    server = Server('', args.port, args.timeout)
    server.run()
    sys.exit(0)