import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import  Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Cryptodome.Cipher import AES

import socket, threading
from utils import *

ROOT_KEY = 'I7xv5oMpgFhWhxiLi3cwAAw9onHQmIwis10TdLWC97Q='
nickname = input("Choose your nickname: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      #socket initialization
client.connect(('127.0.0.1', 7976))                             #connecting client to server

msg_type = {
	'pub_key': '0x01',  #msg with publickey starts with 0x01 
	'message': '0x02',  #general message starts with 0x02
	'other' : '0x00',
	'msg_n_pubKey': '0x03', #message with public_key start with 0x03
}




class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv

class client(object):
	def __init__(self) -> None:
		self.IKc = X25519PrivateKey.generate()
		self.SPKc = X25519PrivateKey.generate()
		self.OPKc = X25519PrivateKey.generate()
		self.DHratchet = X25519PrivateKey.generate()

	def x3DH(self, root_key):
		self.sk = b64_decode(root_key)

	def init_ratchets(self):
		self.root_ratchet = SymmRatchet(self.sk)
		self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
		self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

	def dh_ratchet(self, ):
		pass


def receive():
    while True:                                                 #making valid connection
        try:
            message = client.recv(1024).decode('ascii')
            if message == 'NICKNAME':
                client.send(nickname.encode('ascii'))
            else:
                print(message)
        except:                                                 #case on wrong ip/port details
            print("An error occured!")
            client.close()
            break
def write():
    while True:                                                 #message layout
        message = '{}: {}'.format(nickname, input(''))
        client.send(message.encode('ascii'))

receive_thread = threading.Thread(target=receive)               #receiving multiple messages
receive_thread.start()
write_thread = threading.Thread(target=write)                   #sending messages 
write_thread.start()