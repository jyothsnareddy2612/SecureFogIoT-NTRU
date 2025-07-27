import socket
import threading as th
import time
import base64
import ntru_comm  
def generate_timestamp():
    return int(time.time()) #current time in sec     

class CloudServer:
    def __init__(self,host,port):
        self.host=host
        self.port=port
        self.credentials={}                                             
        self.node_credentials={}  #store fogid-> password
                                       
        self.used_nonce=()  #store nodeid->password
        self.node_SS={}                                              

    def start_server(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.bind((self.host,self.port))
        server.listen(5)
        print(f'Cloud server running on {self.host}:{self.port}')
        while True:
            client,addr=server.accept()      #accept client connection                                
            th.Thread(target=self.handle_client,args=(client,)).start() 

    def handle_client(self,client):
        encrypted = client.recv(4096)
        try:
            msg = ntru_comm.decrypt_message(encrypted)
        except:
            print("[!] Failed to decrypt message from fog.")
            return
        #  Registartion

        if 'register_node' in msg:                       
            _,node_id,password,SS=msg.split(':') #registering node details received from fog

            self.node_credentials[node_id]=ntru_comm.encrypt_message(password)
            self.node_SS[node_id]=ntru_comm.encrypt_message(SS)

        elif 'register' in msg:       #fog registration                  
            _,fog_id,nonce,timestamp=msg.split(':')

            if (self.prevent_replay_attack(timestamp,client)):
                return

              # send ack

            ack_to_fog=f'ACK:{fog_id}:{nonce}'
            client.send(ntru_comm.encrypt_message(ack_to_fog))

            p_msg=client.recv(4096)
            try:
                pass_msg = ntru_comm.decrypt_message(p_msg)
            except:
                print("[!] Failed to decrypt password message.")
                return

            timestamp,password,rec_nonce=pass_msg.split(':')
            if rec_nonce==nonce:
                n=(nonce,)
                self.used_nonce+n
                self.credentials[fog_id]=ntru_comm.encrypt_message(password)
                print(f'Fog-{fog_id} registered successfully...')
                client.send(ntru_comm.encrypt_message(f'ACK:{fog_id} Registration successful..')) #send ack for successful regist
            else:
                print('Registration failed..')
        #inter fog authentication

        elif 'inter_authenticate' in msg:
            _,node_id,password,nonce,timestamp,fog_id=msg.split(':')

            if (self.prevent_replay_attack(timestamp,client)):
                return

            if ntru_comm.decrypt_message(self.node_credentials.get(node_id))==password: #check node credentials received 
                ack_to_fog=f'ACK:{node_id}:{password}:{nonce}:{fog_id} authentication from cloud'
                print(f'Cloud:node authentication successful..')
                client.send(ntru_comm.encrypt_message(ack_to_fog))  #send ack to fog for successful authen
            else:
                print('node authentication failed..\nIncorrect credentials!')
            #Fog Authentication

        elif 'authenticate' in msg:
            _,fog_id,password,nonce,timestamp=msg.split(':')

            if (self.prevent_replay_attack(timestamp,client)):
                return

            if  ntru_comm.decrypt_message(self.credentials.get(fog_id))==password:
                ack_to_fog=f'ACK:{fog_id}'
                print('fog server authentication successful..')
                client.send(ntru_comm.encrypt_message(ack_to_fog))
            else:
                print('fog server authentication failed..\nIncorrect credentials!')

        elif 'failsafe_auth' in msg:
            _,node_id,ss,nonce,timestamp=msg.split(':')

            if (self.prevent_replay_attack(timestamp,client)):
                return

            if  ntru_comm.decrypt_message(self.node_SS.get(node_id))==ss:
                ack_to_fog=f'ACK:{node_id}:{ss} authentication from cloud'
                print(f'Cloud:node fail safe authentication successful..')
                client.send(ntru_comm.encrypt_message(ack_to_fog))
            else:
                print('node authentication failed..\nIncorrect credentials!')

        else:
            print('invalid message format..')

    def getDetails(self):    
        print(self.node_credentials)
        print()
        print(self.credentials)

    def prevent_replay_attack(self,timestamp,client):
        current_time=generate_timestamp()
        if current_time-int(timestamp)>30: #validating time (allow a 30s window)
            client.send(ntru_comm.encrypt_message('Registration failed: timestamp expired'))
            return True
        return False

