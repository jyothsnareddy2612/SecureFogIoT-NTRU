# SecureFogIoT-NTRU
Secure IoT communication system using Fog-Cloud architecture with NTRU encryption.
 Description:
A secure IoT communication system using Fog-Cloud architecture and Ring-LWE lattice-based encryption to ensure quantum-safe and lightweight communication across edge devices.- *Edge Node*: Registers/authenticates via fog or cloud.
- Fog Server: Authenticates edge nodes and coordinates with adjacent fogs.
- Cloud Server: Acts as central authority for backup authentication and credential storage.
## Features
- Post-quantum secure authentication (NTRU, Ring-LWE)
-  Intra-fog, inter-fog, and fail-safe support
-  Nonce and timestamp validation for replay protection
- Shared Secret (SS) generation for symmetric encryption
-  Modular Object-Oriented Python implementation
-  Socket-based communication between nodes
## Technologies Used
- Python 3.x
- Custom implementation of NTRU and Ring-LWE
- Socket Programming (TCP)
- Multi-threading (Python threading)
- NTRU encryption for message transfer
## Setup Instructions
### Prerequisites
- Python 3.x installed
- All project files in the same directory

### Run Order
1. *Run Cloud Server* on one terminal/machine:
   python CloudServer.py
   python FogServer.py
   python EdgeServer.py
   

