import proto

from proxy import UpstreamConnection, DownstreamConnection
from stream import SpotifyCodec
from network import ProxyConnection

from copy import deepcopy
import hexdump

# class ClientManager(object):
#     def __init__(self, upstream_sock):
#         self.upstream = UpstreamConnection(SpotifyCodec(upstream_sock, 'upstream'))
#         self.proxy = ProxyConnection([self.upstream, self.downstream])

#     def run(self):
#         self.proxy.run()

class ProxyManager(object):
    def __init__(self, upstream_sock, downstream_sock):
        self.upstream = UpstreamConnection(SpotifyCodec(upstream_sock, 'upstream'))
        self.downstream = DownstreamConnection(SpotifyCodec(downstream_sock, 'downstream'))

        self.proxy = ProxyConnection({self.upstream, self.downstream})
    
    def run(self):
        self.proxy.run()

    def connect(self):
        # TODO: Single set of keys for both connections?
        downstream_keys = Crypto().generate_keys()
        upstream_keys = Crypto().generate_keys()

        # read hello from client downstream
        downstream_hello, downstream_hello_bytes = self.downstream.codec.recv_unencrypted(proto.ClientHello, initial=True)
        downstream_keys.compute_shared_key(downstream_hello.login_crypto_hello.diffie_hellman.gc)

        # inject our public key into client's hello and pass it upstream
        upstream_hello = deepcopy(downstream_hello)
        upstream_hello.login_crypto_hello.diffie_hellman.gc = upstream_keys.public_key_bytes
        upstream_hello_bytes = self.upstream.codec.send_unencrypted(upstream_hello.SerializeToString(), initial=True)

        # assert len(downstream_hello_bytes) == len(upstream_hello_bytes)

        # read upstream response back
        upstream_resp, upstream_resp_bytes = self.upstream.codec.recv_unencrypted(proto.APResponseMessage)
        upstream_keys.compute_shared_key(upstream_resp.challenge.login_crypto_challenge.diffie_hellman.gs)

        # give downstream our (signed) public key
        downstream_resp = deepcopy(upstream_resp)
        downstream_resp.challenge.login_crypto_challenge.diffie_hellman.gs = downstream_keys.public_key_bytes
        downstream_resp.challenge.login_crypto_challenge.diffie_hellman.gs_signature = downstream_keys.sign_public_key()
        downstream_resp_bytes = self.downstream.codec.send_unencrypted(downstream_resp.SerializeToString())
        # assert len(downstream_resp_bytes) == len(upstream_resp_bytes)

        downstream_keys.compute_challenge(downstream_hello_bytes, downstream_resp_bytes)
        upstream_keys.compute_challenge(upstream_hello_bytes, upstream_resp_bytes)

        # receive downstream's challenge and compare with ours
        downstream_challenge_resp, _ = self.downstream.codec.recv_unencrypted(proto.ClientResponsePlaintext)
        if downstream_keys.challenge != downstream_challenge_resp.login_crypto_response.diffie_hellman.hmac:
            print('error: challenge differed')
            print('\tdownstream client challenge is 0x%s' % downstream_challenge_resp.login_crypto_response.diffie_hellman.hmac.hex())
            print('\tdownstream server challenge is 0x%s' % downstream_keys.challenge.hex())
            return
        
        # send computed challange back upstream
        upstream_challenge_resp = deepcopy(downstream_challenge_resp)
        upstream_challenge_resp.login_crypto_response.diffie_hellman.hmac = upstream_keys.challenge
        self.upstream.codec.send_unencrypted(upstream_challenge_resp.SerializeToString())

        # All done, downstream keys swapped as we are not the client in this instance.
        self.upstream.codec.upgrade(send_key=downstream_keys.send_key, recv_key=downstream_keys.recv_key)
        self.downstream.codec.upgrade(send_key=downstream_keys.recv_key, recv_key=downstream_keys.send_key)
