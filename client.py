import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import  Ed25519PublicKey, Ed25519PrivateKey


from Cryptodome.Cipher import AES

import json
import socket, threading
from utils import *
import ast


###                         ###
# INITIAL CLIENT IS BOB       #
# SUBSEQUENT CLIENT IS ALICE  #
###                         ###

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

class MsgType():
    def __init__(self) -> None:
        self.pub_key = '0x01'
        self.msg = '0x02'
        self.msg_n_pubkey = '0x03'
        self.other = '0x00'

class SymmetricRatchet(object):
    def __init__(self, key) -> None:
        self.state = key
    
    def next(self, inp=b''):
        output = hkdf(self.state + inp, 80)
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
        dh_send = self.DHratchet.exchange(alice_pk)
        shared_send = self.root_ratchet(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)

    def send(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        return cipher, self.DHratchet.public_key()

    def recv(self, cipher, bob_pub_key):
        self.dh_ratchet(bob_pub_key)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))

def receive():
    while True:                                                 #making valid connection
        try:
            message = client.recv(1024).decode('ascii')
            if message == 'NICKNAME':
                init_server_msg = nickname
                client.send(init_server_msg.encode('ascii'))
                client.send(init_pk)
                # client.send(str(type.pub_key+init_pk).encode('ascii'))
            elif message[0:1] == "[":  ## receiving pk bundle from server. 
                available_users =  ast.literal_eval(message) # convert string dictionary to dict format
                print(available_users)
            elif message[0:2] == "b'":
                mes = ast.literal_eval(message)
                global alice_pk
                alice_pk = x25519.X25519PublicKey.from_public_bytes(mes)
                print("PK received from server\nYou can start sending messages")
            else:
                print(message)
        except:                                                 #case on wrong ip/port details
            print("An error occured!")
            client.close()
            break
def write():
    while True:                                                 #message layout
        message = '{}:{}'.format(nickname, input(''))
        client.send(message.encode('ascii'))


type = MsgType()


alice = Client()
pk_obj = alice.DHratchet.public_key()
init_pk = pk_obj.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)

receive_thread = threading.Thread(target=receive)               #receiving multiple messages
receive_thread.start()
write_thread = threading.Thread(target=write)                   #sending messages 
write_thread.start()



