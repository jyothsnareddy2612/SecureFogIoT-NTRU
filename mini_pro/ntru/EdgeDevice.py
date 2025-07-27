import socket
import time
import random
import ntru_comm

def generate_timestamp():
    return int(time.time())  #current time in sec

class EdgeDevice:
    def __init__(self, node_id, password, host, port, fog_id, fog_host, fog_port, SS):
        self.node_id = node_id
        self.password = password
        self.host = host
        self.port = port
        self.fog_id = fog_id
        self.fog_host = fog_host
        self.fog_port = fog_port
        self.SS = SS

    def register_with_fog(self):
         #1.send registration request
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        
        msg = f'register:{self.node_id}:{self.fog_id}:{nonce}:{timestamp}'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.fog_host, self.fog_port))
        s.send(ntru_comm.encrypt_message(msg))
         # 2.receive acknowledgement from 

        ack = ntru_comm.decrypt_message(s.recv(4096))
        print(f'[Node-{self.node_id}] received ack: {ack}')
        if f'ACK:{self.node_id}' in ack:
            _, _, rec_nonce = ack.split(':')
             #verify nonce 
            if int(rec_nonce) == nonce:
                   #3.send password to 
                pwd_msg = f'{self.node_id}:{self.password}:{nonce}:{self.SS}'
                s.send(ntru_comm.encrypt_message(pwd_msg))
                 #4.Receive confirmation from 
                confirm = ntru_comm.decrypt_message(s.recv(4096))
                print(f'[Node-{self.node_id}] confirmation: {confirm}')
            else:
                print('[Node] Nonce mismatch')
        else:
            print('[Node] Invalid registration ack')

    def authenticate_with_fog(self):
         #1.send authentication request
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        msg = f'authenticate:{self.node_id}:{self.password}:{nonce}:{timestamp}'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.fog_host, self.fog_port))
        s.send(ntru_comm.encrypt_message(msg))
         # 2.receive acknowledgement from 
        ack = ntru_comm.decrypt_message(s.recv(4096))
        print(f'[Node-{self.node_id}] auth response: {ack}')

    def inter_fog_authentication(self, fog_host, fog_port):
        #1.send authentication request
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        msg = f'inter_authenticate:{self.node_id}:{self.password}:{nonce}:{timestamp}:{self.fog_id}'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((fog_host, fog_port))
        s.send(ntru_comm.encrypt_message(msg))
         #receive authentication from fog
        ack = ntru_comm.decrypt_message(s.recv(4096))
        print(f'[Node-{self.node_id}] inter-fog response: {ack}')

    def intra_fog_authenticate(self, fog_host, fog_port):
         #1.send authentication request
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        msg = f'intra_authenticate:{self.node_id}:{self.password}:{nonce}:{timestamp}:{self.fog_id}'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((fog_host, fog_port))
        s.send(ntru_comm.encrypt_message(msg))
         #receive authentication from fog
        ack = ntru_comm.decrypt_message(s.recv(4096))
        print(f'[Node-{self.node_id}] intra-fog response: {ack}')

    def fail_safe_mechanism(self):
          #1.send authentication request
        nonce = random.randint(100000, 999999)
        timestamp = generate_timestamp()
        msg = f'failsafe_auth:{self.node_id}:{self.SS}:{nonce}:{timestamp}'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.fog_host, self.fog_port))
        s.send(ntru_comm.encrypt_message(msg))
         #receive authentication from fog
        ack = ntru_comm.decrypt_message(s.recv(4096))
        print(f'[Node-{self.node_id}] fail-safe response: {ack}')
