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
        
    def setup(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(False)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.addr)
        except socket.error as error:
            print("Socket initialization failed!")
            return None

    def run(self, mode=''):
        try:
            while True:
                st_time = timeit.default_timer()
                
                request = input("> ").encode()
                if (request):
                    self.sock.send(request)

                response = self.sock.recvfrom(BUFFER_SIZE)
                if response:
                    print("$", response[0])

                fn_time = timeit.default_timer() - st_time
                # print(f"{fn_time/1000.0:.5f} ms")
        
        except KeyboardInterrupt:
            print("Interrupt: by the user...")
        except Exception as error:
            print("Error:", str(error))
        finally:
            self.sock.close()

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
    client.setup()
    client.run()