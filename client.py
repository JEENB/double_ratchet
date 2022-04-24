from logging import raiseExceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import  Ed25519PublicKey, Ed25519PrivateKey


from Cryptodome.Cipher import AES

import json
import socket, threading
from utils import *
import ast
import time


ROOT_KEY = b"o\x99\xa1\xdd@#\xc0\x0b \xec\xf5\x80GI\xbf\xca\x8b\x16}L;j\x02f\x07'\x88\x8f\x816e4"
nickname = input("Choose your nickname: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      #socket initialization
client.connect(('127.0.0.1', 7976))                             #connecting client to server


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
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print('Send ratchet seed:', b64_encode(shared_send))

    def receive_ratchet(self,alice_pk):
        dh_recv = self.DHratchet.exchange(alice_pk)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print('Recv ratchet seed:', b64_encode(shared_recv))


    def enc(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        return cipher, self.DHratchet.public_key()

    def dec(self, cipher, alice_pk):
        self.receive_ratchet(alice_pk)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print(msg)



alice = Client()
alice.init_ratchets()

pk_obj = alice.DHratchet.public_key()
init_pk = pk_obj.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)


'''
Initial Client is alice, subsequent client is BOB

Here Bob tries to communicate with Alice first



'''

def receive():
    while True: #making valid connection
        try:
            message = client.recv(2048).decode('utf-8')

            if message == 'NICKNAME':  #hello message received from the server. 
                # print("##                       ##")
                # print("#   Registration Phase    #")
                # print("##                       ##")
                init_server_msg = nickname
                client.send(init_server_msg.encode('utf-8'))
                client.send(init_pk)

            
            elif message[0:1] == "[":  ## receiving pk bundle from server i.e a list. 
                available_users =  ast.literal_eval(message) # convert list
                print(available_users)

            elif message[0:4] == "Talk":
                print("Who would you like to talk to??")

            elif message[0:2] == "b'" or message[0:2] == 'b"':   ## if message is pubkey then starts with b(byte)
                global alice_pk
                if message[-2] == "=":
                    # print("received_msg_nPK", alice_pk)
                    byte_msg = ast.literal_eval(message)
                    decode_msg = b64_decode(byte_msg)
                    # print("decoded msg:", decode_msg)
                    alice.dec(decode_msg, alice_pk)
                else:
                    mes = ast.literal_eval(message)
                    # print(len(mes))
                    alice_pk = x25519.X25519PublicKey.from_public_bytes(mes)
                    print("PK received")
            else:
                print(message)
        except Exception as e:                                                 #case on wrong ip/port details
            print(e)
            print("An error occured!")
            client.close()
            break
def write():
    count = 0

    while True:                                 #message layout
        message = '{}:{}'.format(nickname, input(''))
        count += 1
        try:
            if alice_pk:
                count = 2
        except:
            pass
        if count > 1: 
            alice.dh_ratchet(alice_pk)
            cipher, pk = alice.enc(message)
            pk_byte = pk_to_bytes(pk)
            client.send(str(pk_byte).encode('utf-8'))
            time.sleep(0.5)
            c = b64_encode(cipher)
            client.send(str(c).encode('utf-8'))
        else:
            client.send(str(message).encode('utf-8'))

receive_thread = threading.Thread(target=receive)               #receiving multiple messages
receive_thread.start()
write_thread = threading.Thread(target=write)                   #sending messages 
write_thread.start()



