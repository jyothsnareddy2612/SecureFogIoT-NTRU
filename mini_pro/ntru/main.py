import socket
import threading 
import time
import random
from CloudServer import CloudServer as cs
from FogServer import FogServer as fs
from EdgeDevice import EdgeDevice as ed

# Create Cloud Server
cloud = cs('127.0.0.1', 5555)
time.sleep(1)

# Create Fog Servers
fog1a = fs('f1a', '1233', '127.0.0.1', 6666, '127.0.0.1', 5555, '127.0.0.1', 6667)
time.sleep(1)
fog1b = fs('f1b', '1234', '127.0.0.1', 6667, '127.0.0.1', 5555, '127.0.0.1', 6666)
time.sleep(1)
fog2 = fs('f2', '3433', '127.0.0.1', 7777, '127.0.0.1', 5555)
time.sleep(2)

# Create Edge Devices
edge1a = ed('n1', '4556', '127.0.0.1', 8888, 'f1a', '127.0.0.1', 6666, 56)
edge2 = ed('n2', '4326', '127.0.0.1', 9999, 'f2', '127.0.0.1', 7777, 66)
edge1b = ed('n3', '4557', '127.0.0.1', 8889, 'f1b', '127.0.0.1', 6667, 98)

def start_servers():
    cloud_thread = threading.Thread(target=cloud.start_server)
    fog1a_thread = threading.Thread(target=fog1a.start_server)
    fog1b_thread = threading.Thread(target=fog1b.start_server)
    fog2_thread = threading.Thread(target=fog2.start_server)

    cloud_thread.start()
    fog1a_thread.start()
    fog1b_thread.start()
    fog2_thread.start()

if __name__ == '__main__':
    print("Starting Cloud and Fog Servers...\n")
    start_servers()
    time.sleep(1)

    print("Registering Fog Servers with Cloud...\n")
    fog1a.register_with_cloud()
    print("\n--------------------------------------\n")
    fog1b.register_with_cloud()
    print("\n--------------------------------------\n")
    fog2.register_with_cloud()
    print("\n--------------------------------------\n")

    print("Authenticating Fog Servers with Cloud...\n")
    fog1a.authenticate_with_cloud()
    print("\n--------------------------------------\n")
    fog1b.authenticate_with_cloud()
    print("\n--------------------------------------\n")
    fog2.authenticate_with_cloud()
    print("\n--------------------------------------\n")

    print("Registering Edge Devices with their respective Fog Servers...\n")
    edge1a.register_with_fog()
    print("\n--------------------------------------\n")
    edge2.register_with_fog()
    print("\n--------------------------------------\n")

    print("Authenticating Edge Devices...\n")
    edge1a.authenticate_with_fog()
    print("\n--------------------------------------\n")
    edge2.authenticate_with_fog()
    print("\n--------------------------------------\n")

    # Inter-Fog Authentication (edge1a moves from fog1a to fog2)
    print("Performing Inter-Fog Authentication...\n")
    edge1a.inter_fog_authentication('127.0.0.1', 7777)
    print("\n--------------------------------------\n")

    # Intra-Fog Authentication (edge1a authenticates with fog1b)
    print("Performing Intra-Fog Authentication...\n")
    edge1a.intra_fog_authenticate('127.0.0.1', 6667)
    print("\n--------------------------------------\n")

    # Fail-Safe Mechanism for edge2
    print("Performing Fail-Safe Authentication for edge2...\n")
    edge2.fail_safe_mechanism()
    print("\n--------------------------------------\n")

    print("All operations completed for multi cloud-fog-edge setup.\n")
