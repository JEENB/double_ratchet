import socket
import threading   
import json                                             #Libraries import

host = '127.0.0.1'                                                      #LocalHost
port = 7976                                                             #Choosing unreserved port

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)              #socket initialization
server.bind((host, port))                                               #binding host and port to socket
server.listen()

clients = []
nicknames = []
pub_key_bundle = {}

def broadcast(message):                                                 #broadcast function declaration
    for client in clients:
        client.send(message)

def handle(client):                                         
    while True:
        try:                                                            #recieving valid messages from client
            message = client.recv(1024).decode('ascii')
            act_msg = message.split(":")[1]
            print(act_msg)
            if act_msg in nicknames:
                print(True)
                send_pk = pub_key_bundle[act_msg]
                print(send_pk)
                client.send(str(send_pk).encode('ascii'))
            else:
                broadcast(message.encode('ascii'))
        except:                                                         #removing clients
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast('{} left!'.format(nickname).encode('ascii'))
            nicknames.remove(nickname)
            break

def receive():                                                          #accepting multiple clients
    while True:
        client, address = server.accept()
        print("Connected with {}".format(str(address)))   

        #send initial message to client    
        client.send('NICKNAME'.encode('ascii'))

        #receive nickname and pk from client
        nickname = client.recv(2048).decode('ascii')
        client_pk = client.recv(2048)
        pub_key_bundle[nickname] = client_pk
        nicknames.append(nickname)
        clients.append(client)

        print("Nickname is {}".format(nickname))
        print(f'[{nickname}]: PK received')
        broadcast("{} joined!".format(nickname).encode('ascii'))
        client.send('Connected to server!'.encode('ascii'))

        #sending public key bundle to client
        pk_bundle_endoded = "\nAvailable Users\n" + str(nicknames)
        client.send(pk_bundle_endoded.encode('ascii'))
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

receive()