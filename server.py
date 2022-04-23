import socket
import threading   
import json
import time


host = '127.0.0.1'                                                      #LocalHost
port = 7976                                                             #Choosing unreserved port

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)              #socket initialization
server.bind((host, port))                                               #binding host and port to socket
server.listen()

clients = []
nicknames = []
pub_key_bundle = {}

class MessageType:
    def __init__(self) -> None:
        self.pk = 0x01
        self.message = 0x02

msg_type = MessageType()

def broadcast(message):                                                 #broadcast function declaration
    for client in clients:
        client.send(message)

def handle(client):                                         
    while True:
        try:                                                            #recieving valid messages from client
            time.sleep(5)
            message = client.recv(1024).decode('utf-8')
            print(message)
            try:
                act_msg = message.split(":")[1]
                print(act_msg)
            except:
                act_msg = message
            if act_msg in nicknames:
                # print(True)
                send_pk = pub_key_bundle[act_msg]
                type = str(msg_type.pk)
                print(send_pk)
                client.send(str(send_pk).encode('utf-8'))
            else:
                broadcast(message.encode('utf-8'))
        except:                                                         #removing clients
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast('{} left!'.format(nickname).encode('utf-8'))
            nicknames.remove(nickname)
            break

def receive():                                                          #accepting multiple clients
    while True:
        client, address = server.accept()
        print("Connected with {}".format(str(address)))   

        #send initial message to client    
        client.send('NICKNAME'.encode('utf-8'))

        #receive nickname and pk from client
        nickname = client.recv(2048).decode('utf-8')
        client_pk = client.recv(2048)
        pub_key_bundle[nickname] = client_pk
        nicknames.append(nickname)
        clients.append(client)

        print("Nickname is {}".format(nickname))
        print(f'[{nickname}]: PK received')
        broadcast("{} joined!".format(nickname).encode('utf-8'))
        client.send('Connected to server!'.encode('utf-8'))


        #sending public key bundle to client
        pk_bundle_endoded = "\nAvailable Users\n" + str(nicknames)
        client.send(pk_bundle_endoded.encode('utf-8'))
        
        # time.sleep(0.5)
        # client.send("Talk".encode('utf-8'))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

receive()