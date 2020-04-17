#!/usr/bin/env python3
# coding: utf-8

import dns
import sys
import socket
import timeit
import argparse
import threading

DEBUG = None

class Server():
    def __init__(self, host, port, timeout=30):
        self.addr = (host, port)
        self.hostname = socket.gethostname()
        self.timeout = timeout

        try:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setblocking(1)
            self.tcp_sock.bind(self.addr)

            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setblocking(0)
            self.udp_sock.bind(self.addr)

        except socket.error as error:
            print("Socket initialization failed:", str(error))
            return None

    def tcp_listen(self):          
        self.tcp_sock.listen(1)
        
        while True:
            connection, addr = self.tcp_sock.accept()
            connection.settimeout(self.timeout)
            connection.setblocking(True)
            
            st_time = timeit.default_timer()
            
            with connection:
                request = connection.recv(dns.BUFFER_SIZE)
                if not request:
                    print(f"Client disconnected!")
                    break
                        
                print(f"Received", f"{len(request)} bytes", end=" ")

                response = str.encode("Got it!")
                connection.send(response)

            fn_time = timeit.default_timer() - st_time
            print(f"{fn_time/1000.0:.5f} ms")
        
        # self.tcp_sock.close()

    def udp_listen(self):
        self.udp_sock.settimeout(self.timeout)

        while True:
            st_time = timeit.default_timer()
            
            request, addr = self.udp_sock.recvfrom(dns.BUFFER_SIZE)
            if not request:
                raise error(f"Client at {addr} disconnected!")
                        
            print("Received data from", addr, f"{len(request)} bytes", end=" ")

            response = request.upper()
            self.udp_sock.sendto(response, addr)

            fn_time = timeit.default_timer() - st_time
            print(f"{fn_time/1000.0:.5f} ms")
        
        self.udp_sock.close()

    def run(self):
        try:
            threading.Thread(target=self.tcp_listen).start()
            print(f"TCP thread running on {self.hostname}:{self.addr[1]}")
            
            threading.Thread(target=self.udp_listen).start()
            print(f"UDP thread running on {self.hostname}:{self.addr[1]}")
        except KeyboardInterrupt:
            print("Interrupt: by the user...")
        except Exception as error:
            print("Error:", str(error))

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