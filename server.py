#!/usr/bin/env python3
# coding: utf-8

import sys
import json
import base64
import random
import select
import socket
import hashlib
import argparse
import textwrap

import dnslib as dns
import exfiltration as exf

DEBUG = None

class Server():
    def __init__(self, host, port, timeout):
        self.addr = (host, port)
        self.hostname = socket.gethostname()
        self.timeout = timeout
        self.zones = []
        self.sockets = []

        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.bind(self.addr)
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
        print(f"Server is running. Timeout is {self.timeout} secs")
        try:
            readable, writable, exceptional = select.select(self.sockets, [], [], self.timeout)
            while readable:
                for sock in readable:
                    if sock.type == socket.SOCK_DGRAM:
                        self.process_udp(sock)
                    
                    if sock.type == socket.SOCK_STREAM:
                        if sock == self.tcp_sock:
                            self.accept_tcp(sock)
                        else:
                            self.process_tcp(sock)

                readable, writable, exceptional = select.select(self.sockets, [], [], self.timeout)

        except KeyboardInterrupt:
            print("[Interrupt] Exit by the user...")
        except Exception as error:
            print("[Info]", str(error))
        except socket.timeout:
            print("[Info]", "Timed out! Exiting...")

        print("Server is shutting down!")
        for sock in self.sockets:
            sock.close()
        return
 
    def process_udp(self, sock):
        request, addr = sock.recvfrom(exf.SOCK_BUFFER_SIZE)
        if request:
            response = self.dns_resolve(request)
            sock.sendto(response, addr)
        else:
            return

    def accept_tcp(self, sock):
        c, addr = sock.accept()
        c.settimeout(self.timeout)
        self.sockets += [c]

    def process_tcp(self, sock):
        try:
            request = sock.recv(exf.SOCK_BUFFER_SIZE)
            if request:
                response = self.dns_resolve(request)
                sock.send(response)
        except:
            sock.close()
            self.sockets.remove(sock)
            return

    def dns_resolve(self, data):
        request = dns.DNSRecord.parse(data)
        reply = request.reply()
        
        qname = str(request.q.get_qname())
        qtype = request.q.qtype
        qdata = getattr(dns, dns.QTYPE.get(qtype))

        og_data = exf.domain_decode(qname, base64.urlsafe_b64decode)
        #hash_data = hashlib.sha1(og_data).digest()

        hash_data = og_data

        # og_rr = random.choice([x for x in self.zones if x.rtype == qtype])
        # reply.add_answer(og_rr)

        reply.add_answer(dns.RR(qname, rtype=dns.QTYPE.TXT, rdata=dns.TXT(hash_data)))

        return reply.pack()

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="DNS server script")

    parser.add_argument('-z', '--zone-file', dest="config", required=True,
                        help='Specifies zone file (describes a DNS zone)')
    
    parser.add_argument('-p', '--port', dest='port', type=int, default=53,
                        help='Specifies the port that the server will listen to')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    parser.add_argument('-t', '--timeout', dest='timeout', type=int, default=60,
                        help='Specifies the timeout for incoming connections')

    args = parser.parse_args()

    server = Server('', args.port, args.timeout)
    server.load_config(args.config)
    server.run()
    sys.exit(0)