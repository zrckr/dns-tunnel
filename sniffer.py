#!/usr/bin/env python3
# coding: utf-8

import re
import sys
import math
import time
import socket
import struct
import argparse
import dnslib as dns
import datetime as dt
import exfiltration as exf

DEBUG = False
GOOD = False

BUFFER = 65565
DNS_PORT = 53
DNS_MIN_SIZE = 64
DNS_SIZE = 128
DNS_SEC_SIZE = 512
DNS_RR_MAX = 10
DNS_USUAL_DOMAIN_SIZE = 52

# Malicious QTYPE
EXF_QTYPE = [dns.QTYPE.A, dns.QTYPE.AAAA, dns.QTYPE.CNAME, 
                dns.QTYPE.TXT, dns.QTYPE.MX, dns.QTYPE.NS]

# Old QTYPE: MD, MF, NULL, WKS
OBS_QTYPE = [ 3, 4, 10, 11 ]

# Exclude SRV and PTR
EXC_QTYPE = [dns.QTYPE.SRV, dns.QTYPE.PTR]

# Only NOERROR and NXDOMAIN statuses
ONLY_RCODE = [dns.RCODE.NOERROR, dns.RCODE.NXDOMAIN]

# Detect base64, base32 strings
BASE_REGEX = '^(?:[a-zA-Z0-9+\/]{4})*(?:|(?:[a-zA-Z0-9+\/]{3}=)|(?:[a-zA-Z0-9+\/]{2}==)|(?:[a-zA-Z0-9+\/]{1}===))$'
# Detect IPv4 address strings
IP_REGEX = '^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$'

def print_with_time(message):
    curr_time = dt.datetime.now().strftime("%H:%M:%S.%f")
    print(f"[{curr_time[:-3]}]", message)

# --------------------------------------------------------------------------------------------------
class PcapFile:
    """ Class for writting to PCAP file only """
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
    """ Simple class for describing the IPv4 header """
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
    """ Simple class for describing the TCP header """
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
    """ Simple class for describing the UDP header """
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
    """ Main sniffer class """
    def __init__(self, filename):
        self.sock = None
        self.pcap = PcapFile(filename)
        self.base_pattern = re.compile(BASE_REGEX)
        self.packets = {-1: 0}
        self.count = 0

    def setup(self, ip):    
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.sock.bind((ip, 0))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.pcap.write_header()

    def run(self, minutes):
        t_end = time.time() + 60 * minutes
        while time.time() < t_end:
            try:
                 self.sniff_dns()
            except KeyboardInterrupt:
                print("[Exit]", "Interrupt by the user...")
                break
        print(self.packets)

    def sniff_dns(self):
        """ 
            Sniffs data from gateway address (network interface) and
            analyzes DNS payload if it present.
        """
        packet, _ = self.sock.recvfrom(BUFFER)
        dns_payload = b''
        ports = 0

        # Process IPv4 header information
        raw = struct.unpack("!BBHHHBBH4s4s", packet[0:20])
        ip = IPv4(raw)
        # print(ip)

        if ip.protocol == TCP.IP_PDU:
            # Process TCP header information
            raw = struct.unpack("!HHLLBBHHH", packet[ip.length:ip.length+20])
            tcp = TCP(raw)
            ports = (tcp.src_port, tcp.dst_port)
            
            # Extract DNS payload from TCP message
            if (tcp.dst_port == DNS_PORT or tcp.src_port == DNS_PORT):             
                size = ip.length + tcp.length * 4 + 2
                dns_payload = packet[size:]

        if ip.protocol == UDP.IP_PDU:
            # Process UDP header information
            raw = struct.unpack("!HHHH", packet[ip.length:ip.length+8])
            udp = UDP(raw)
            ports = (udp.src_port, udp.dst_port)
            
            # Extract DNS payload from UDP message
            if (udp.dst_port == DNS_PORT or udp.src_port == DNS_PORT):             
                size = ip.length + 8
                dns_payload = packet[size:]

        if dns_payload:
            # Discard the truncated DNS message 
            if (exf.check_bit(dns_payload, 22)):
                return

            self.count += 1
            dns_packet = dns.DNSRecord.parse(dns_payload)
            dns_type = dns_packet.q.qtype

            # Count messages for one RR type
            if (dns_type not in self.packets):
                self.packets[dns_type] = 0
            else:
                self.packets[dns_type] += 1
            
            # Analyze the DNS message
            probability, spy_domain = self.analyze_dns(dns_payload)
            if (probability > 0.66):
                # Maybe, this sniffed message is for DNS-tunnel
                self.packets[-1] += 1
                print_with_time(f"[{self.count}] {spy_domain}: {ip.src_addr}:{ports[0]} > {ip.dst_addr}:{ports[1]} | {len(packet)}")
            
            self.pcap.write_packet(packet)

    def analyze_dns(self, raw):
        """ 
            Analyzes DNS payload for the presence of the DNS-tunneling data.
            Returns probability of its presence in the network.
        """

        record = dns.DNSRecord.parse(raw)
        domain = record.q.get_qname()
        root_domain = b'.'.join(domain.label[-2:]).decode()

        checks = [
            self.check_types(record),
            self.check_fqdn(domain),
            self.check_sizes(record, domain),
            self.check_rr_count(record),
            self.check_entropy(str(domain), 4.5),
            self.check_entropy(raw, 4.7),
            # self.check_resolve(str(domain))
        ]
        
        is_spy = sum(checks) / len(checks)
        return is_spy, root_domain

    def check_fqdn(self, domain) -> bool:
        """
            Checks FQDN with Base64 regex.
        """
        string = b''.join(domain.label[:-2])
        r_check = self.base_pattern.findall(string.decode()) 

        if (r_check and string):
            return True
        else:
            return False

    def check_sizes(self, record, domain) -> bool:
        """
            Checks sizes of various components of DNS message.
        """
        raw_again = record.pack()
        if (len(raw_again) > DNS_SIZE):
            if (len(str(domain)) > DNS_USUAL_DOMAIN_SIZE):
                return True

            max_size = 0.0
            for rr in record.rr:
                data = str(rr.rdata)
                if (len(data) > DNS_USUAL_DOMAIN_SIZE):
                    max_size = len(data)
                
            if max_size > DNS_SIZE:
                return True
        return False

    def check_rr_count(self, record) -> bool:
        """
            Checks count of RR in Answers Section.
        """
        # Checking types of RR
        if len(record.rr) > DNS_RR_MAX:
            count = 0.0
            for rr in record.rr:
                if (rr.rtype in EXF_QTYPE or rr.rtype in OBS_QTYPE):
                    count += 1.0
                
            if (count / len(record.rr) > 0.66):
                return True
        return False

    def check_types(self, record) -> bool:
        """
            Checks types of requested or responded RR.
        """
        # Checking the rcode flag
        if record.header.rcode not in ONLY_RCODE:
            return False

        # Check SOA
        if record.auth:
            if record.auth[0].rtype == dns.QTYPE.SOA:
                return False
        
        # Checking the question type
        if record.q.qtype in EXC_QTYPE:
            return False
        elif record.q.qtype in EXF_QTYPE or record.q.qtype in OBS_QTYPE:
            return True
        else:
            return False

    def check_entropy(self, data, barier) -> bool:
        """
            Checks entropy of raw binary data with some limit value.
        """
        new_entropy = self.__shannon__(data)
        if (new_entropy > barier):
            return True
        return False

    def check_resolve(self, hostname):
        """
            Checks the actual resolving (for testing purposes).
        """
        try:
            socket.gethostbyname(hostname)
            return False
        except socket.error:
            return True

    def __shannon__(self, data) -> float:
        """
            Calculates the Shannon's entropy of some data.
        """
        # We determine the frequency of each byte
        # in the dataset and if this frequency is not null we use it for the
        # entropy calculation
        ent = 0.0
        freq = {}   
        
        for c in data:
            if c in freq:
                freq[c] += 1
            else:
                freq[c] = 1

        # A byte can take 256 values from 0 to 255. Here we are looping 256 times
        # to determine if each possible value of a byte is in the dataset
        for key in freq.keys():
            f = float(freq[key]) / len(data)
            if f > 0:   # to avoid an error for log(0)
                ent = ent + f * math.log(f, 2)
        return -ent

# --------------------------------------------------------------------------------------------------             
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS-tunneling project: sniffer script for detecting the tunnel")
    
    parser.add_argument('-g', '--gateway', dest='ip', type=str, required=True,
                        help='Specifies the gateway address')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    parser.add_argument('-f', '--filename', dest='path', type=str, default="capture.pcap", required=True,
                        help='Specifies path for .pcap file')

    parser.add_argument('-m', '--minutes', dest='minutes', type=int, default=1,
                        help='Size of the time window in minutes for traffic analysis')

    args = parser.parse_args()
    if not (re.compile(IP_REGEX).match(args.ip)):
        parser.error("Invalid IP gateway address!")

    if (args.minutes <= 0):
        parser.error("Minutes must be > 0!")

    DEBUG = args.debug

    print_with_time(f"[Info] Sniffer is running for {args.minutes} minutes!")

    s = Sniffer(filename=args.path)
    s.setup(ip=args.ip)
    s.run(minutes=args.minutes)