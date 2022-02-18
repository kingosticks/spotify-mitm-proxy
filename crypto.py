

import os

import pyshn as shn
import hashlib
import hmac
from pathlib import Path


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (dh, padding, rsa, utils)


PRIVATE_KEY_PEM_FILE = Path('ourserver_private_key.pem')


def int_from_bytes(data):
    return int.from_bytes(data, 'big')


def int_to_bytes(bn, length=None):
    if length is None:
        length = (bn.bit_length() + 7) // 8
    return bn.to_bytes(length, 'big')


def public_key_to_bytes(public_key):
    return int_to_bytes(public_key.public_numbers().y)


def load_rsa_private_key(key_file):
    if not key_file.is_file():
        print(f"Cannot open private key pem file {key_file}")
        return

    private_key = serialization.load_pem_private_key(
        key_file.read_bytes(),
        password=None,
        backend=default_backend())
    return private_key


def load_rsa_public_key_bytes(key_file=PRIVATE_KEY_PEM_FILE)
    if key_file.is_file():
        private_key = load_rsa_private_key(key_file)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # TODO: and serialize private key
    return public_key_to_bytes(private_key.public_key())


def gen_signature(pub):
    key_index = 0
    key_pub_prime = 0x10001

DH_generator = 2
DH_prime = int_from_bytes([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9,
        0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6,
        0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e,
        0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
        0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e,
        0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a,
        0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14,
        0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
        0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4,
        0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

class Crypto(object):
    def __init__(self):
        self._private_key = None
        self._public_key = None
        self.public_key_bytes = None
        # self.remote_key = None
        self.shared_key = None
        self.send_key = None
        # self.send_cipher = None
        self.recv_key = None
        # self.recv_cipher = None
        self.challenge = None
        self.signing_key_file = PRIVATE_KEY_PEM_FILE

    def generate_keys(self, key = None):
        dh_numbers = dh.DHParameterNumbers(p=DH_prime, g=DH_generator)
        dh_parameters = dh_numbers.parameters(backend=default_backend())
        # dh_parameters = dh.generate_parameters(generator=DH_generator, key_size=95 * 8)  95??
        self._private_key = dh_parameters.generate_private_key()
        self._public_key = self.private_key.public_key()
        self.public_key_bytes = public_key_to_bytes(self._public_key)
        print(f"Generated DH keys")
        return self

    def compute_shared_key(self, remote_key):
         self.shared_key = self._private_key.exchange(remote_key)

    def sign_public_key(self):
        if self.public_key_bytes is None:
            return
        rsa_private_key = load_rsa_private_key(self.signing_key_file)        
        return = rsa_private_key.sign(self.public_key_bytes), padding.PKCS1v15(), hashes.SHA1())

    def compute_challenge(self, client_packet, server_packet): # SpotifyCodec.setup_encrypted_streams used instead
        data = bytes()
        for i in range(1,6):
            h = hmac.new(self.shared_key, digestmod=hashlib.sha1)
            h.update(client_packet)
            h.update(server_packet)
            h.update(i)
            data += h.digest()

        mac = hmac.new(data[0:0x14], digestmod=hashlib.sha1)
        mac.update(client_packet)
        mac.update(server_packet)
        self.challenge = mac.digest()

        self.send_key = data[0x14:0x34]
        # self.send_cipher = shn.Shannon(self.send_key)

        self.recv_key = data[0x34:0x54]
        # self.recv_cipher = shn.Shannon(self.recv_key)

