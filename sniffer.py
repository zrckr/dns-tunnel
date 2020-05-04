#!/usr/bin/env python3
# coding: utf-8

import re
import sys
import time
import socket
import struct
import dnslib as dns

HOST = ("192.168.0.74", 0)
BUFFER = 65565
DNS_PORT = 53

EXF_QTYPE = [
    dns.QTYPE.A,
    dns.QTYPE.AAAA, 
    dns.QTYPE.CNAME, 
    dns.QTYPE.TXT, 
    dns.QTYPE.MX,
    dns.QTYPE.NS,
]

OBS_QTYPE = [
    3,  # MD
    4,  # MF
    10, # NULL
    11, # WKS
]

class PcapFile:
    def __init__(self, filename):
        self.filename = filename

    def write_header(self):
        """ Writes global header to .pcap file"""
        """ struct pcap_hdr:
                u32 magic_number;       /* magic number */
                u16 version_major;      /* major version number */
                u16 version_minor;      /* minor version number */
                i32 thiszone;           /* GMT to local correction */
                u32 sigfigs;            /* accuracy of timestamps */
                u32 snaplen;            /* max length of captured packets, in octets */
                u32 network;            /* data link type */
        """
        pcap_hdr = struct.pack("!I 2H i 3I", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        with open(self.filename, 'wb') as file:
            file.write(pcap_hdr)

    def write_packet(self, data):
        """ 
            Writes packet header and packet data to .pcap file.
            Additionaly writes Ethernet II frame header.
        """
        eth_hdr = struct.pack("!6s 6s H", b'\xfe\xed\xfa\xce\xbe\xef', b'\x13\x37\x33\x01\x21\x03', 0x0800)
        raw = eth_hdr + data
        
        """ struct pcaprec_hdr:
                u32 ts_sec;         /* timestamp seconds */
                u32 ts_usec;        /* timestamp microseconds */
                u32 incl_len;       /* number of octets of packet saved in file */
                u32 orig_len;       /* actual length of packet */
        """
        pcaprec_hdr = struct.pack("!4I", int(time.time()), 0, len(raw), len(raw))
        with open(self.filename, 'ab') as file:
            file.write(pcaprec_hdr + raw)

class IPv4:
    def __init__(self, header):
        self.version = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.length = self.ihl * 4
        self.ttl = header[5]
        self.protocol = header[6]
        self.src_addr = socket.inet_ntoa(header[8])
        self.dst_addr = socket.inet_ntoa(header[9])

    def __repr__(self):
        return "[IPv4] ver: {0}, ihl: {1}, len: {2}, ttl: {3}, proto: {4}, src: {5}, dst: {6}".format(
            self.version, self.ihl, self.length, self.ttl, self.protocol, self.src_addr, self.dst_addr)

class TCP:
    IP_PDU = 6
    def __init__(self, header):
        self.src_port = header[0]
        self.dst_port = header[1]
        self.seq = header[2]
        self.ack = header[3]
        self.doff = header[4]
        self.length = header[4] >> 4

    def __repr__(self):
        return "[TCP] src: {0}, dst: {1}, seq: {2}, ack: {3}, len: {4}".format(
            self.src_port, self.dst_port, self.seq, self.ack, self.length)

class UDP:
    IP_PDU = 17 
    def __init__(self, header):
        self.src_port = header[0]
        self.dst_port = header[1]
        self.length = header[2]
        self.checksum = header[3]

    def __repr__(self):
        return '[UDP] src: {0}, dst: {1}, len: {2}, crc: {3}'.format(
            self.src_port, self.dst_port, self.length, self.checksum)

class Sniffer:
    def __init__(self, filename):
        self.sock = None
        self.pcap = PcapFile(filename)
        self.count = 0

    def setup(self):    
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.sock.bind(HOST)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.pcap.write_header()

    def run(self, count):
        self.count = count
        
        while(self.count):
            self.count -= self.sniff_dns()

    def sniff_dns(self):
        packet, _ = self.sock.recvfrom(BUFFER)
        dns_payload = None

        raw = struct.unpack("!BBHHHBBH4s4s", packet[0:20])
        ip = IPv4(raw)
        # print(ip)

        if ip.protocol == TCP.IP_PDU:
            raw = struct.unpack("!HHLLBBHHH", packet[ip.length:ip.length+20])
            tcp = TCP(raw)
            # print(tcp)

            if (tcp.dst_port == DNS_PORT or tcp.src_port == DNS_PORT):             
                size = ip.length + tcp.length * 4
                dns_payload = packet[size:]

        if ip.protocol == UDP.IP_PDU:
            raw = struct.unpack("!HHHH", packet[ip.length:ip.length+8])
            udp = UDP(raw)
            # print(udp)

            if (udp.dst_port == DNS_PORT or udp.src_port == DNS_PORT):             
                size = ip.length + 8
                dns_payload = packet[size:]

        if dns_payload:
            parsed = dns.DNSRecord.parse(dns_payload)
            qtype = parsed.q.qtype

            if qtype in EXF_QTYPE or qtype in OBS_QTYPE:
                
                print(f'** [{self.count:04}] **' + '*' * 68)
                print(parsed)
                print()

                self.pcap.write_packet(packet)
                return 1
        
        return 0
                      
if __name__ == "__main__":
    s = Sniffer(filename="other/bad_dns.pcap")
    s.setup()
    s.run(count=50)