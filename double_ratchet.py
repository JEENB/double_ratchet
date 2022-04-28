
from Cryptodome.Cipher import AES
from logging import raiseExceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import  Ed25519PublicKey, Ed25519PrivateKey

from utils import *

ROOT_KEY = b"o\x99\xa1\xdd@#\xc0\x0b \xec\xf5\x80GI\xbf\xca\x8b\x16}L;j\x02f\x07'\x88\x8f\x816e4"

class SymmetricRatchet(object):
    def __init__(self, key) -> None:
        self.state = key
    
    def next(self, inp=b''):
        # print("state",self.state)
        output = hkdf(self.state + inp, 80)
        # print(output)
        self.state = output[:32]
        outkey = output[32:64]
        iv = output[64:]
        return outkey, iv
    
class Client(object):
    def __init__(self) -> None:
        self.DHratchet = X25519PrivateKey.generate()
        self.sk = ROOT_KEY

    def init_ratchets(self):
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, alice_pk):
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_pk)
        print("\n** Key State **")
        print(f"Diffie Hellman Key: {str(b64_encode(dh_send), 'utf-8')}") 
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print(f"Send ratchet seed:{str(b64_encode(shared_send),'utf-8')}\n")

    def receive_ratchet(self,alice_pk):
        dh_recv = self.DHratchet.exchange(alice_pk)
        print("\n** Key State **")
        print(f"Diffie Hellman Key: {str(b64_encode(dh_recv), 'utf-8')}")
        
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print(f"Recv ratchet seed:, {str(b64_encode(shared_recv), 'utf-8')}\n")


    def enc(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print(f"Send Cipher Text: {str(b64_encode(cipher), 'utf-8')}")
        return cipher, self.DHratchet.public_key()

    def dec(self, cipher, alice_pk):
        self.receive_ratchet(alice_pk)
        key, iv = self.recv_ratchet.next()
        print(f"Receive Cipher Text: {str(b64_encode(cipher), 'utf-8')}\n")
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print(str(msg,'utf-8'))
        return(str(msg, 'utf-8'))