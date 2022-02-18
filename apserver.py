import socketserver
import proto
import struct
import random
import os
from crypto import Crypto
from crypto import bin2bn, bn2bin
import socket
import hashlib
import hmac
import time
import json
import sys
from select import select

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


SPOTIFY_HOST = '104.199.65.124'
SPOTIFY_PORT = 4070

import session

class SpotifyTCPHandler(socketserver.BaseRequestHandler):
    allow_reuse_address = True

    def handle(self):
        print('handling')
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192 * 32)
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192 * 32)

        while True:
            try:
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream_sock.connect((SPOTIFY_HOST, SPOTIFY_PORT))
                #print('Connected upstream sock')

                upstream_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                upstream_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192 * 32)
                upstream_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192 * 32)

                proxy = session.ProxyManager(upstream_sock, self.request)

                print('Making proxy connection to', SPOTIFY_HOST, SPOTIFY_PORT)
                proxy.connect()
                print()
                proxy.run()
            except KeyboardInterrupt:
                return
            except Exception as exc:
                print(exc)
                pexit(1)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 4070
    server = socketserver.TCPServer((HOST, PORT), SpotifyTCPHandler)
    server.allow_reuse_address = True
    print("Ready to go... on %s:%s" % (HOST, PORT))
    #server.handle_request()
    server.serve_forever()
