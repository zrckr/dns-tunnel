#!/usr/bin/env python3
# coding: utf-8

import sys
import queue
import select
import socket
import argparse
import constants as cn
import exfiltration as exf

DEBUG = None

class Server():
    def __init__(self, host, port, timeout=30):
        self.addr = (host, port)
        self.hostname = socket.gethostname()
        self.timeout = timeout
        self.sockets = []

        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.bind(self.addr)
            self.tcp_sock.listen()
        
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(self.addr)

            self.sockets += [self.tcp_sock, udp_sock]

        except socket.error as error:
            print("[Socket] Initialization failed:", str(error))
            return None

    def run(self):
        print("Server is running!")
        try:
            while True:
                readable, writable, exceptional = select.select(self.sockets, [], [])
                for sock in readable:
                    if sock.type == socket.SOCK_DGRAM:
                        self.process_udp(sock)
                    
                    if sock.type == socket.SOCK_STREAM:
                        if sock == self.tcp_sock:
                            self.accept_tcp(sock)
                        else:
                            self.process_tcp(sock)

        except KeyboardInterrupt:
            print("[Interrupt] Exit by the user...")
        except Exception as error:
            print("[Info]", str(error))

        print("Server is shutting down!")
        for sock in self.sockets:
            sock.close()
        return

    def main(self, data):
        return exf.dns_proc_q(data)
    
    def process_udp(self, sock):
        request, addr = sock.recvfrom(cn.SOCK_BUFFER_SIZE)
        if request:
            response = self.main(request)
            sock.sendto(response, addr)
        else:
            return

    def accept_tcp(self, sock):
        c, addr = sock.accept()
        self.sockets += [c]

    def process_tcp(self, sock):
        try:
            request = sock.recv(cn.SOCK_BUFFER_SIZE)
            if request:
                response = self.main(request)
                sock.send(response)
        except:
            sock.close()
            self.sockets.remove(sock)
            return

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

    client = Server('', args.port)
    client.run()