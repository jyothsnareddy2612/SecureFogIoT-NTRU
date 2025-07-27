import socket
import threading as th
import time
import random
import ntru_comm

def generate_timestamp():
    return int(time.time())  #current time in sec

class FogServer:
    def __init__(self, fog_id, password, host, port, cloud_host, cloud_port, adj_fog_host=None, adj_fog_port=None):
        self.fog_id = fog_id
        self.password = password
        self.host = host
        self.port = port
        self.cloud_host = cloud_host
        self.cloud_port = cloud_port
        self.adj_fog_host = adj_fog_host
        self.adj_fog_port = adj_fog_port
        self.node_credentials = {}  #local storage for nodeid->password
        self.used_nonces = {}  # Stores nonces with timestamps to prevent replay attacks.

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f'Fog server {self.fog_id} running on {self.host}:{self.port}')
        while True:
            client, _ = server.accept()
            th.Thread(target=self.handle_client, args=(client,)).start()

    def register_with_cloud(self):
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        request_msg = f'register:{self.fog_id}:{nonce}:{timestamp}'
        cloud = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cloud.connect((self.cloud_host, self.cloud_port))
        cloud.send(ntru_comm.encrypt_message(request_msg))

        ack_msg = ntru_comm.decrypt_message(cloud.recv(4096))
        print(f'[Fog-{self.fog_id}] received ack: {ack_msg}')

        if f'ACK:{self.fog_id}' in ack_msg:
            _, fog_id, rec_nonce = ack_msg.split(':')
            if int(rec_nonce) == nonce:
                print('[Fog] Ack verified')
                pwd_msg = f'{timestamp}:{self.password}:{nonce}'
                cloud.send(ntru_comm.encrypt_message(pwd_msg))
                confirmation = ntru_comm.decrypt_message(cloud.recv(4096))
                print(f'[Fog-{self.fog_id}] Cloud confirmation: {confirmation}')
            else:
                print('[Fog] Invalid nonce in ack')
        else:
            print('[Fog] Invalid ack format')

    def authenticate_with_cloud(self):
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        request_msg = f'authenticate:{self.fog_id}:{self.password}:{nonce}:{timestamp}'
        cloud = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cloud.connect((self.cloud_host, self.cloud_port))
        cloud.send(ntru_comm.encrypt_message(request_msg))

        ack_msg = ntru_comm.decrypt_message(cloud.recv(4096))
        print(f'[Fog-{self.fog_id}] Authentication response: {ack_msg}')

    def handle_client(self, client):
        try:
            msg = ntru_comm.decrypt_message(client.recv(4096))
        except:
            client.close()
            return

        print(f'[Fog-{self.fog_id}] Received: {msg}')
         #######  Registartion 

        if msg.startswith('register'): #node registration
            _, node_id, f_id, nonce, timestamp = msg.split(':')

            # Prevent replay by checking if the nonce is already used
            if nonce in self.used_nonces:
                client.send(ntru_comm.encrypt_message('Registration failed: nonce already used'))
                return

            # Store the nonce with the timestamp to prevent replay
            self.used_nonces[nonce] = generate_timestamp()

            if (self.prevent_replay_attack(timestamp,client)):
                return
             # send ack

            ack = f'ACK:{node_id}:{nonce}'
            client.send(ntru_comm.encrypt_message(ack))
            
            #receive password

            p_msg = ntru_comm.decrypt_message(client.recv(4096))
            node_id, password, rec_nonce, SS = p_msg.split(':')
            if rec_nonce == nonce:
                self.node_credentials[node_id] = ntru_comm.encrypt_message(password)
                print(f'[Fog-{self.fog_id}] Node {node_id} registered.')
                client.send(ntru_comm.encrypt_message(f'ACK:{node_id} Registration successful.'))

                cloud = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                cloud.connect((self.cloud_host, self.cloud_port))
                cloud.send(ntru_comm.encrypt_message(f'register_node:{node_id}:{password}:{SS}'))
            else:
                client.send(ntru_comm.encrypt_message('Registration failed: nonce mismatch'))
    #node authentication
        elif msg.startswith('authenticate'):
            _, node_id, password, nonce, timestamp = msg.split(':')

            # Prevent replay by checking if the nonce is already used
            if nonce in self.used_nonces:
                client.send(ntru_comm.encrypt_message('Authentication failed: nonce already used'))
                return

            # Store the nonce with the timestamp to prevent replay
            self.used_nonces[nonce] = generate_timestamp()

            if (self.prevent_replay_attack(timestamp,client)):
                return

            encrypted = self.node_credentials.get(node_id)
             #check credentials
            if encrypted and ntru_comm.decrypt_message(encrypted) == password:
                client.send(ntru_comm.encrypt_message(f'ACK:{node_id}'))
                print(f'[Fog-{self.fog_id}] Node {node_id} authenticated.')
            else:
                client.send(ntru_comm.encrypt_message('Authentication failed'))


    #####inter fog authentication
        elif msg.startswith('inter_authenticate'):
            _, node_id, password, nonce, timestamp, fogid = msg.split(':')
            if (self.prevent_replay_attack(timestamp,client)):
                return
            cloud = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cloud.connect((self.cloud_host, self.cloud_port))
            cloud.send(ntru_comm.encrypt_message(f'inter_authenticate:{node_id}:{password}:{nonce}:{timestamp}:{fogid}'))
            ack = ntru_comm.decrypt_message(cloud.recv(4096))
            if "ACK" in ack:
                ack=f'Inter-fog Auth successfull...'
                client.send(ntru_comm.encrypt_message(ack))
            else:
                client.send(ntru_comm.encrypt_message('Authentication failed...'))

           
            #####intra fog authentication

        elif msg.startswith('intra_authenticate'):  #request by node
            _, node_id, password, nonce, timestamp, fogid = msg.split(':')

            # Prevent replay by checking if the nonce is already used
            if nonce in self.used_nonces:
                client.send(ntru_comm.encrypt_message('Intra-fog authentication failed: nonce already used'))
                return
            if (self.prevent_replay_attack(timestamp,client)):
                return

            # Store the nonce with the timestamp to prevent replay
            self.used_nonces[nonce] = generate_timestamp()

            if self.adj_fog_host and self.adj_fog_port:
                adj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                adj.connect((self.adj_fog_host, self.adj_fog_port))
                adj.send(ntru_comm.encrypt_message(f'intra_fog_authenticate:{node_id}:{password}:{nonce}:{timestamp}:{fogid}'))
                ack = ntru_comm.decrypt_message(adj.recv(4096))
                
                if "ACK" in ack:
                    ack=f'Intra-fog Auth successfull...'
                    client.send(ntru_comm.encrypt_message(ack))
                else:
                    client.send(ntru_comm.encrypt_message('Authentication failed...'))
            else:
                client.send(ntru_comm.encrypt_message('Authentication failed: No adjacent fog'))

        elif msg.startswith('intra_fog_authenticate'): ##request by another fog 
    
            _, node_id, password, nonce, timestamp, fogid = msg.split(':')
            if (self.prevent_replay_attack(timestamp,client)):
                return
            stored = self.node_credentials.get(node_id)
            if stored and ntru_comm.decrypt_message(stored) == password: #check node credentials received from fog

                client.send(ntru_comm.encrypt_message(f'ACK:{node_id}:{password}'))
            else:
                client.send(ntru_comm.encrypt_message('Authentication failed by original fog'))

        elif msg.startswith('failsafe_auth'):
             #send to cloud
            _, node_id, ss, nonce, timestamp = msg.split(':')
            if (self.prevent_replay_attack(timestamp,client)):
                return
            cloud = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cloud.connect((self.cloud_host, self.cloud_port))
            cloud.send(ntru_comm.encrypt_message(f'failsafe_auth:{node_id}:{ss}:{nonce}:{timestamp}'))
             #ack from cloud
            ack = ntru_comm.decrypt_message(cloud.recv(4096))
            if 'ACK' in ack:
                ack=f'ACK:{node_id}:{self.fog_id} fail safe auth successful'
                client.send(ntru_comm.encrypt_message(ack))
            else:
                ack=f'Authenticatio failed...'
                client.send(ntru_comm.encrypt_message(ack))

        else:
            client.send(ntru_comm.encrypt_message('Invalid message format'))

    def getDetails(self):
        print(f"[Fog-{self.fog_id}] Stored encrypted node credentials:")
        print(self.node_credentials)

    def prevent_replay_attack(self,timestamp,client):
        current_time=generate_timestamp()
        if current_time-int(timestamp)>30: #validating time (allow a 30s window)
            client.send(ntru_comm.encrypt_message('Registration failed: timestamp expired'))
            return True
        return False
