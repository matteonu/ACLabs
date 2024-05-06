import json
import os
import socket
from string import printable

ALPHABET = printable

from Crypto.PublicKey import ElGamal
from server.elgamal import ElGamalImpl
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50902

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================

fd = socket.create_connection(
    (HOST if REMOTE else "localhost", PORT)).makefile("rw")

def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def get_public_parameters() -> tuple[int,int,int]:
    response = run_command({"command": "get_public_parameters"})
    return int(response["p"]), int(response["g"])

def send_encrypted_message(c1: bytes, c2: bytes):
    response = run_command({"command": "encrypted_command",
                            "encrypted_command": {
                                "c1": c1.hex(),
                                "c2": c2.hex()
                            }})
    encrypted_res = response["encrypted_res"]
    return bytes.fromhex(encrypted_res["c1"]), bytes.fromhex(encrypted_res["c2"])

def set_response_key(key: ElGamal.ElGamalKey):
    response = run_command({"command": "set_response_key",
                            "p": str(key.p),
                            "g": str(key.g),
                            "y": str(key.y)})
    return response["res"]

def compute_K(c_2: bytes, ptxt: bytes, p: int) -> int:
    message_as_long = bytes_to_long(ptxt)
    ptxt_inv = number.inverse(message_as_long, p) % p
    return (bytes_to_long(c_2) * ptxt_inv) % p

def send_backdoor_command(p, c_0, K):
    new_ptxt = bytes_to_long(b'backdoor')
    c_2 = (K * new_ptxt) % p
    return send_encrypted_message(c_0, long_to_bytes(c_2))


p, g = get_public_parameters()
encrypted_response = send_encrypted_message(int(1).to_bytes(1, 'big'), b'1')
K = compute_K(encrypted_response[1], b'Ran into an exception:Nice try!', p)
own_elgamal_key = ElGamal.generate(256, os.urandom)
set_response_key(own_elgamal_key)
encrypted_flag = send_backdoor_command(p, encrypted_response[0], K)
ptxt = ElGamalImpl.decrypt(own_elgamal_key, encrypted_flag[0], encrypted_flag[1])
print(ptxt)
