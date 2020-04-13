#!/usr/bin/env python3
# coding: utf-8

import sys
import socket
import timeit
import argparse

DEBUG = None
BUFFER_SIZE = 1024

class Server():
    def __init__(self, host, port, timeout):
        self.sock = None
        self.addr = (host, port)
        self.timeout = timeout
        self.cancelled = False
        
    def setup(self, max_connections):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(False)
            self.sock.settimeout(self.timeout)
            self.sock.bind(self.addr)
            #self.sock.listen(max_connections)

            print(f"Listening on {socket.gethostname()}:{self.addr[1]}, timeout {self.timeout}...")
        except socket.error as error:
            print("Socket initialization failed:", str(error))
            return None

    def run(self, mode=''):
        try:
            while True:
                st_time = timeit.default_timer()

                request, host = self.sock.recvfrom(BUFFER_SIZE)
                if not request:
                    break
                print("Received data from", host, f"{len(request)} bytes", end=" ")

                response = bytes([len(bytes.decode(request))])
                if response:
                    self.sock.sendto(response, host)

                fn_time = timeit.default_timer() - st_time
                print(f"{fn_time/1000.0:.5f} ms")

        except KeyboardInterrupt:
            print("Interrupt: by the user...")
        except Exception as error:
            print("Error:", str(error))
        finally:
            self.sock.close()

# --------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="Server script"
    )
    parser.add_argument('-p', '--port', dest='port', type=int, required=True,
                        help='Specifies the port that the server will listen to')

    parser.add_argument('-d', '--debug', dest='debug', action="store_true",
                        help='Displays debugging information')

    parser.add_argument('-mc', '--max-conns', dest='conns', type=int,
                        help="Specifies the number of maximum connections to the server")

    args = parser.parse_args()

    client = Server('', args.port, 5)
    client.setup(args.conns)
    client.run()