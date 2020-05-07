#!/usr/bin/env python3
# coding: utf-8

import re
import sys
import time
import socket
import struct
import hashlib
import argparse
import dnslib as dns
import datetime as dt

BUFFER = 65565
DNS_PORT = 53
DNS_MIN_SIZE = 64
DNS_MAX_SIZE = 512
DNS_SEC_MAX_SIZE = 4096
DNS_RR_MAX = 10

# Malicious QTYPE
EXF_QTYPE = [dns.QTYPE.A, dns.QTYPE.AAAA, dns.QTYPE.CNAME, 
                dns.QTYPE.TXT, dns.QTYPE.MX, dns.QTYPE.NS]

# Old QTYPE: MD, MF, NULL, WKS
OBS_QTYPE = [ 3, 4, 10, 11 ]

# Exclude SRV and PTR
EXC_QTYPE = [dns.QTYPE.SRV, dns.QTYPE.PTR]

# Only NOERROR and NXDOMAIN statuses
ONLY_RCODE = [dns.RCODE.NOERROR, dns.RCODE.NXDOMAIN]

# Detecting base64, base32 strings
BASE_REGEX = '^(?:[a-zA-Z0-9+/\-_]{4})*(?:|(?:[a-zA-Z0-9+/\-_]{3}=)|(?:[a-zA-Z0-9+/\-_]{2}==)|(?:[a-zA-Z0-9+/\-_]{1}===))$'
IP_REGEX = '^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$'

def print_with_time(head, message):
    curr_time = dt.datetime.now().strftime("%H:%M:%S.%f")
    print(f"[{head}] [{curr_time[:-3]}]", message)

# --------------------------------------------------------------------------------------------------
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

# --------------------------------------------------------------------------------------------------
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

# --------------------------------------------------------------------------------------------------
class Sniffer:
    def __init__(self, filename):
        self.sock = None
        self.pcap = PcapFile(filename)
        self.count = 0
        self.base_pattern = re.compile(BASE_REGEX)
        self.domains = {}

    def setup(self, ip):    
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.sock.bind((ip, 0))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.pcap.write_header()

    def run(self, count):
        if not (count):
            count = sys.maxsize

        for i in range(count):
            try:
                 self.sniff_dns()
            except KeyboardInterrupt:
                print("[Exit]", "Interrupt by the user...")
                break

    def sniff_dns(self):
        packet, _ = self.sock.recvfrom(BUFFER)
        osi_4 = ""
        dns_payload = b''

        raw = struct.unpack("!BBHHHBBH4s4s", packet[0:20])
        ip = IPv4(raw)
        # print(ip)

        if ip.protocol == TCP.IP_PDU:
            raw = struct.unpack("!HHLLBBHHH", packet[ip.length:ip.length+20])
            tcp = TCP(raw)
            osi_4 = str(tcp)
            
            if (tcp.dst_port == DNS_PORT or tcp.src_port == DNS_PORT):             
                size = ip.length + tcp.length * 4 + 2
                dns_payload = packet[size:]

        if ip.protocol == UDP.IP_PDU:
            raw = struct.unpack("!HHHH", packet[ip.length:ip.length+8])
            udp = UDP(raw)
            osi_4 = str(udp)
            
            if (udp.dst_port == DNS_PORT or udp.src_port == DNS_PORT):             
                size = ip.length + 8
                dns_payload = packet[size:]

        if dns_payload:
            parsed = dns.DNSRecord.parse(dns_payload)
            checks = 0

            # Checking the rcode flag
            if parsed.header.rcode not in ONLY_RCODE:
                return

            # Checking the question type
            qtype = parsed.q.qtype
            if qtype in EXC_QTYPE:
                return
            elif qtype in EXF_QTYPE or qtype in OBS_QTYPE:
                checks += 1

            # Check if domain name contains base64 or base32 string
            odd_domain = str(parsed.q.get_qname())
            if (self.base_pattern.match(odd_domain)):
                checks += 1

            # Check if main domain name is already in dict
            main_domain = '.'.join(odd_domain.split('.')[-3:])
            main_domain_md5 = hashlib.md5(main_domain.encode()).hexdigest()
            
            if main_domain not in self.domains:
                self.domains[main_domain] = main_domain_md5
            elif self.domains[main_domain] == main_domain_md5:
                checks += 1

            # Check for big dns messages (non-UDP)
            if len(dns_payload) > DNS_MAX_SIZE:
                checks += 1

            # Checking types of RR
            if len(parsed.rr) > DNS_RR_MAX:
                for rr in parsed.rr:
                    count = 0.0
                    if (rr.rtype in EXF_QTYPE or rr.rtype in OBS_QTYPE):
                        count += 1.0
                
                    if (count / len(parsed.rr) > 0.66):
                        checks += 1
                        break

            if (checks > 2):
                self.pcap.write_packet(packet)
                print(osi_4)
                print(parsed)
                print(f'** [{self.count:04}] **' + '*' * 68)

# --------------------------------------------------------------------------------------------------             
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniffer script for detecting DNS tunnel")
    
    parser.add_argument('-g', '--gateway', dest='ip', type=str, required=True,
                        help='Specifies the gateway address')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    parser.add_argument('-f', '--filename', dest='path', type=str, default="capture.pcap", required=True,
                        help='Specifies path for .pcap file')

    parser.add_argument('-c', '--count', dest='count', type=int, default=0,
                        help='Specifies number of captured DNS messages in .pcap file.' + 
                            'If value is 0 - will capture until user interrupt occurs.')              

    args = parser.parse_args()
    if not (re.compile(IP_REGEX).match(args.ip)):
        print("Parser error: invalid IP gateway address!")
        sys.exit(1)

    print("[Info]", f"Listening {args.ip}")

    s = Sniffer(filename=args.path)
    s.setup(ip=args.ip)
    s.run(count=args.count)