#!/usr/bin/env python3
# coding: utf-8

import dns
import sys
import socket
import timeit
import argparse

DEBUG = None
BUFFER_SIZE = 1024

class Client():
    def __init__(self, host, port, timeout=30):
        self.sock = None
        self.addr = (host, port)
        self.timeout = timeout
    
    def send(self, data, protocol):
        with socket.socket(socket.AF_INET, protocol) as sock:
            if protocol is socket.SOCK_STREAM:
                sock.setblocking(True)
            sock.settimeout(self.timeout)

            sock.connect(self.addr)
            sock.send(data)

            response = sock.recv(dns.BUFFER_SIZE)
            if not response:
                raise Exception('Sending a request successfully failed!')
            return response

    def run(self):
        try:
            while True:
                size = int(input("Bytes: "))
                
                data = dns.random_bytes(size)
                r = None
                if (len(data) > dns.BIG_DNS):
                    r = self.send(data, socket.SOCK_STREAM)
                else:
                    r = self.send(data, socket.SOCK_DGRAM)
                
                print("$", r)
                
        except KeyboardInterrupt:
            print("[Interrupt] Exit by the user...")
        except Exception as error:
            print("[Info]", str(error))
        except socket.error as error:
            print("[Socket]", str(error))

# --------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="Client script"
    )
    parser.add_argument('-c', '--connect', dest='conn', type=str, required=True,
                        help='Establishes a connection to the server at the specified address:port')
    
    parser.add_argument('-st', '--send-text', dest='text', action='store_true',
                        help='Sends a text string to the server')
    parser.add_argument('-sf', '--send-file', dest='file', type=str,
                        help='Sends the file to the server. The file path is required.')
    parser.add_argument('-sr', '--send-random', dest='rand', action='store_true',
                        help='Sends a random byte array to the server')

    parser.add_argument('-rr', '--rdata-type', dest='rdata', type=str,
                        help='Specifies the type of record to attach data to for transmission')

    args = parser.parse_args()
    
    if (args.text and args.file and args.rand) or\
        (not args.text and not args.file and not args.rand) or\
        (args.text and args.file) or\
        (args.text and args.rand) or\
        (args.file and args.rand):
       parser.error('Only or at least one sending mode must be specified!')

    dest = args.conn.split(':')
    client = Client(dest[0], int(dest[1]))
    client.run()