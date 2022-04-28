# import all the required modules
import socket
import threading
from tkinter import *
from tkinter import font
from tkinter import ttk
from utils import *


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
# import all functions /
# everything from chat.py file

PORT = 7976
SERVER = "127.0.0.1"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

# Create a new client socket
# and connect to the server
client = socket.socket(socket.AF_INET,
					socket.SOCK_STREAM)
client.connect(ADDRESS)

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
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmetricRatchet(shared_send)
        print("\n** Key State **")
        print(f"Diffie Hellman Key: {str(b64_encode(dh_send), 'utf-8')}")
        print('Send ratchet seed:', str(b64_encode(shared_send),'utf-8'))

    def receive_ratchet(self,alice_pk):
        dh_recv = self.DHratchet.exchange(alice_pk)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print("\n** Key State **")
        print(f"Diffie Hellman Key: {str(b64_encode(dh_recv), 'utf-8')}")
        print('Recv ratchet seed:', str(b64_encode(shared_recv), 'utf-8'))


    def enc(self, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print(f"\nSend Cipher: {str(b64_encode(cipher), 'utf-8')}")
        return cipher, self.DHratchet.public_key()

    def dec(self, cipher, alice_pk):
        print(f"\nRecv Cipher: {str(b64_encode(cipher), 'utf-8')}")

        self.receive_ratchet(alice_pk)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print(str(msg,'utf-8'))
        return(str(msg, 'utf-8'))
		
alice = Client()
alice.init_ratchets()

pk_obj = alice.DHratchet.public_key()
init_pk = pk_obj.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)


'''
Initial Client is alice, subsequent client is BOB

Here Bob tries to communicate with Alice first



'''

# GUI class for the chat
class GUI:
	# constructor method
	def __init__(self):
	
		# chat window which is currently hidden
		self.Window = Tk()
		self.Window.withdraw()
		
		# login window
		self.login = Toplevel()
		# set the title
		self.login.title("Login")
		self.login.resizable(width = False,
							height = False)
		self.login.configure(width = 400,
							height = 300)
		# create a Label
		self.pls = Label(self.login,
					text = "Please login to continue",
					justify = CENTER,
					font = "Helvetica 14 bold")
		
		self.pls.place(relheight = 0.15,
					relx = 0.2,
					rely = 0.07)
		# create a Label
		self.labelName = Label(self.login,
							text = "Name: ",
							font = "Helvetica 12")
		
		self.labelName.place(relheight = 0.2,
							relx = 0.1,
							rely = 0.2)
		
		# create a entry box for
		# tyoing the message
		self.entryName = Entry(self.login,
							font = "Helvetica 14")
		
		self.entryName.place(relwidth = 0.4,
							relheight = 0.12,
							relx = 0.35,
							rely = 0.2)
		
		# set the focus of the cursor
		self.entryName.focus()
		
		# create a Continue Button
		# along with action
		self.go = Button(self.login,
						text = "CONTINUE",
						font = "Helvetica 14 bold",
						command = lambda: self.goAhead(self.entryName.get()))
		
		self.go.place(relx = 0.4,
					rely = 0.55)
		self.Window.mainloop()

	def goAhead(self, name):
		self.login.destroy()
		self.layout(name)
		
		# the thread to receive messages
		rcv = threading.Thread(target=self.receive)
		rcv.start()

	# The main layout of the chat
	def layout(self,name):
	
		self.name = name
		self.alice_pk = None
		# to show chat window
		self.Window.deiconify()
		self.Window.title("SASTA Signal")
		self.Window.resizable(width = False,
							height = False)
		self.Window.configure(width = 470,
							height = 550,
							bg = "#17202A")
		self.labelHead = Label(self.Window,
							bg = "#17202A",
							fg = "#EAECEE",
							text = self.name ,
							font = "Helvetica 13 bold",
							pady = 5)
		
		self.labelHead.place(relwidth = 1)
		self.line = Label(self.Window,
						width = 450,
						bg = "#ABB2B9")
		
		self.line.place(relwidth = 1,
						rely = 0.07,
						relheight = 0.012)
		
		self.textCons = Text(self.Window,
							width = 20,
							height = 2,
							bg = "#17202A",
							fg = "#EAECEE",
							font = "Helvetica 14",
							padx = 5,
							pady = 5)
		
		self.textCons.place(relheight = 0.745,
							relwidth = 1,
							rely = 0.08)
		
		self.labelBottom = Label(self.Window,
								bg = "#ABB2B9",
								height = 80)
		
		self.labelBottom.place(relwidth = 1,
							rely = 0.825)
		
		self.entryMsg = Entry(self.labelBottom,
							bg = "#2C3E50",
							fg = "#EAECEE",
							font = "Helvetica 13")
		
		# place the given widget
		# into the gui window
		self.entryMsg.place(relwidth = 0.74,
							relheight = 0.06,
							rely = 0.008,
							relx = 0.011)
		
		self.entryMsg.focus()
		
		# create a Send Button
		self.buttonMsg = Button(self.labelBottom,
								text = "Send",
								font = "Helvetica 10 bold",
								width = 20,
								bg = "#ABB2B9",
								command = lambda : self.sendButton(self.entryMsg.get()))
		
		self.buttonMsg.place(relx = 0.77,
							rely = 0.008,
							relheight = 0.06,
							relwidth = 0.22)
		
		self.textCons.config(cursor = "arrow")
		
		# create a scroll bar
		scrollbar = Scrollbar(self.textCons)
		
		# place the scroll bar
		# into the gui window
		scrollbar.place(relheight = 1,
						relx = 0.974)
		
		scrollbar.config(command = self.textCons.yview)
		
		self.textCons.config(state = DISABLED)

	# function to basically start the thread for sending messages
	def sendButton(self, msg):
		self.textCons.config(state = DISABLED)
		self.msg=msg
		self.entryMsg.delete(0, END)
		snd= threading.Thread(target = self.sendMessage)
		snd.start()

	# function to receive messages
	def receive(self):
		while True:
			try:
				message = client.recv(2048).decode(FORMAT)
				# print(message)
				
				# if the messages from the server is NAME send the client's name
				if message == 'NICKNAME':
					init_server_msg = self.name
					client.send(init_server_msg.encode('utf-8'))
					client.send(init_pk)

				elif message[0:1] == "[":  ## receiving pk bundle from server i.e a list. 
					available_users =  ast.literal_eval(message) # convert list
					self.textCons.config(state = NORMAL)
					self.textCons.insert(END,
										available_users+"\n\n")
					
					self.textCons.config(state = DISABLED)
					self.textCons.see(END)
                
				elif message[0:2] == "b'" or message[0:2] == 'b"':   ## if message is pubkey then starts with b(byte)
					global alice_pk
					if message[-2] == "=":
						# print("received_msg_nPK", alice_pk)
						byte_msg = ast.literal_eval(message)
						decode_msg = b64_decode(byte_msg)
						# print("decoded msg:", decode_msg)
						out = alice.dec(decode_msg, self.alice_pk)
						self.textCons.config(state = NORMAL)
						self.textCons.insert(END,
											out+"\n\n")
						
						self.textCons.config(state = DISABLED)
						self.textCons.see(END)
					else:
						mes = ast.literal_eval(message)
						# print(len(mes))
						self.alice_pk = x25519.X25519PublicKey.from_public_bytes(mes)
						print("PK received")
				else:
					# insert messages to text box
					self.textCons.config(state = NORMAL)
					self.textCons.insert(END,
										message+"\n\n")
					
					self.textCons.config(state = DISABLED)
					self.textCons.see(END)
			except:
				# an error will be printed on the command line or console if there's an error
				print("An error occured!")
				client.close()
				break
		
	# function to send messages
	def sendMessage(self):
		self.textCons.config(state=DISABLED)
		while True:                                 #message layout
			message = (f"{self.name}:{self.msg}")
			display_msg =  (f"you:{self.msg}")		
			if self.alice_pk is not None:
				self.textCons.config(state = NORMAL)
				self.textCons.insert(END,
									display_msg+"\n\n")
				
				self.textCons.config(state = DISABLED)
				self.textCons.see(END)
				alice.dh_ratchet(self.alice_pk)
				cipher, pk = alice.enc(message)
				pk_byte = pk_to_bytes(pk)
				client.send(str(pk_byte).encode('utf-8'))
				time.sleep(0.5)
				c = b64_encode(cipher)
				client.send(str(c).encode('utf-8'))
				break
			else:
				client.send(str(message).encode('utf-8'))
				break

# create a GUI class object
g = GUI()
