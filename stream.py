from enum import Enum
from pyshn import Shannon
import hmac
import hashlib
from crypto import Crypto
from dataclasses import dataclass
import struct
import socket
import threading

PROTOCOL_VERSION = bytes([0, 4])

MAC_SIZE = 4
READ_BLOCK_SIZE = 4096

from apserver import SPOTIFY_HOST, SPOTIFY_PORT


@dataclass(frozen=True)
class PacketHeader:
    command: int
    size: int


class SocketStream:
    def __init__(self, sock):
        self._sock = sock
        self.sock_lock = threading.Lock()

    def reconnect(self):
        raise ValueError('uh oh')
        # upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # upstream_sock.connect((SPOTIFY_HOST, SPOTIFY_PORT))

        # return upstream_sock

    def read_exact(num_bytes):
        buf = bytearray(num_bytes)
        view = memoryview(buf)
        while num_bytes:
            recv_bytes = self._sock.recv_into(view, num_bytes) # flags=socket.MSG_WAITALL ??
            if not recv_bytes:
                raise ValueError("Socket closed")
            view = view[recv_bytes:]
            num_bytes -= recv_bytes

        if num_bytes:
            raise ValueError(f"Failed to read all {len(buf)} bytes")

        return buf

    def send_all(buf):
        sent = 0
        while sent < len(buf):
            remaining = len(buf) - sent
            to_send = min(READ_BLOCK_SIZE, remaining)

            try:
                this_sent = self._sock.send(buf[sent:sent + to_send])
            except socket.error as ex:
                print('stream %r had socket error while sending' % self)
                self._sock = self.reconnect()
                continue
                # raise ex

            if this_sent <= 0:
                print('failed to send', this_sent)

            sent += this_sent

class EncryptedStream(SocketStream):
    def __init__(self, sock, key, name=None):
        super().__init__(sock)
        self.cipher = Shannon(key)
        self.name = name
        self.needs_reset = False

    def __repr__(self):
        return self.name


class EncryptedWriteStream(EncryptedStream):
    def __init__(self, sock, key, name=None):
        super().__init__(sock, key, name)

    def write_packet(self, command, payload):
        with self.sock_lock:

            # print 'payload len is', len(payload)
            buf = struct.pack('>BH', command, len(payload))
            buf += payload

            # print 'resetting write cipher, current nonce is 0x%x (0x%s)' % (
            #     self.cipher.nonce, struct.pack('>L', self.cipher.nonce).encode('hex'))

            if self.needs_reset and self.cipher.nonce == 0x17:
                print('!!!! RESETING NONCE TO ZERO')
                self.cipher.nonce = 0

            self.cipher.reset()

            buf = self.cipher.encrypt(buf)

            mac = self.cipher.finish(MAC_SIZE)
            buf += mac

            self.cipher.nonce += 1

            self.send_all(buf)


class EncryptedReadStream(EncryptedStream):
    HEADER_SIZE = 3

    def __init__(self, sock, key, name=None):
        super().__init__(sock, key, name)
        self.unpacker = struct.Struct('>BH')
        self.packet = None

    def read_packet()(self):
        self.read_packet_header()
        return self.read_packet_body()

    def read_packet_header(self):
        with self.sock_lock:
            if self.packet is not None:
                return

            # print 'resetting read cipher, current nonce is 0x%x (0x%s)' % (
            #     self.cipher.nonce, struct.pack('>L', self.cipher.nonce).encode('hex'))

            self.cipher.reset()

            # print 'have encrypted header 0x%s' % hdrbytes.encode ('hex')
            try:
                header_bytes = self.read_exact(HEADER_SIZE)
                header_bytes = self.cipher.decrypt(header_bytes)
                # print 'have decrypted header 0x%s' % hdrbytes.encode ('hex')
                self.packet = PacketHeader(unpacker.unpack(header_bytes))
                print(f"cmd: 0x{self.packet.command.hex()}, length: {self.packet.size} bytes")
            except ValueError as ex:
                print('failed to read', ex)

            return self.packet

    def read_packet_body(self):
        with self.sock_lock:
            if self.packet is None:
                return (None, None)

            # now read the payload
            try:
            payload_bytes = self.read_exact(self.packet.size + MAC_SIZE)
            packet_bytes = memoryview(payload_bytes)[:self.packet.size]
            
            decrypted_payload = self.cipher.decrypt(packet_bytes)
            our_mac = self.cipher.finish(MAC_SIZE)
            their_mac = memoryview(payload_bytes)[self.packet.size:]

            if our_mac != their_mac:
                print('error: invalid mac')
                print("\twe have mac 0x%s" % our_mac.hex())
                print("\tthey have mac 0x%s" % their_mac.hex())
                print('\tnonce is at 0x%x' % self.cipher.nonce)
                raise ValueError("invalid mac")

            self.cipher.nonce += 1
            command = self.packet.command
            self.packet = None

        return (command, decrypted_payload)


class SpotifyCodec:
    def __init__(self, sock, name):
        self.sock = SocketStream(sock)
        self.name = name

        self.length_format = struct.Struct('>I') # big-endian unsigned int
 
        self.enc_write_stream = None
        self.enc_read_stream = None

        self.stream_lock = threading.Lock()

    def upgrade(self, send_key, recv_key):
        self.sock._sock.setblocking(False)
        self.enc_write_stream = EncryptedWriteStream(self.sock, send_key, name=self.name + ' write')
        self.enc_read_stream = EncryptedReadStream(self.sock, recv_key, name=self.name + ' read')

    def recv_encrypted_header(self):
        return self.enc_read_stream.read_packet_header()

    def recv_encrypted_body(self, as_obj=None):
        cmd, payload = self.enc_read_stream.read_packet_body()
        if cmd is None:
            # socket dead
            return (None, None)

        if as_obj is not None:
            obj = as_obj()
            obj.ParseFromString(payload)
            return (cmd, obj)
        else:
            return (cmd, payload)

    def recv_unencrypted(self, message_type, initial=False):
        header_bytes = bytes()

        if initial:
            header_bytes = self.sock.read_exact(len(PROTOCOL_VERSION))
            if header_bytes != PROTOCOL_VERSION:
                raise ValueError(
                    f"Bad protocol version {header_bytes.hex()}, expected {PROTOCOL_VERSION.hex()}")

        length_bytes = self.sock.read_exact(self.length_format.size)
        assert len(length_bytes) == self.length_format.size
        data_length = self.length_format.unpack(length_bytes)[0] - self.length_format.size - len(header_bytes)

        data_bytes = self.sock.read_exact(data_length)
        obj = message_type().ParseFromString(data_bytes)
        return (obj, header_bytes + length_bytes + data_bytes)

    def send_encrypted(self, cmd, payload):
        # self.check_wire_empty()
        self.enc_write_stream.write_packet(cmd, payload)

    def send_unencrypted(self, data, initial=False):
        # self.check_wire_empty()

        if initial:
            hdr = PROTOCOL_VERSION
        else:
            hdr = bytes()

        length = len(hdr) + self.length_format.size + len(data)

        buf = hdr + self.length_format.pack(length) + data
        self.sock.send_all(buf)

        return buf
