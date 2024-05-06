import json
import os
import socket
from string import printable

ALPHABET = printable

from Crypto.PublicKey import ElGamal
from server.elgamal import ElGamalImpl

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50901

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

def get_public_key() -> tuple[int,int,int]:
    response = run_command({"command": "get_public_key"})
    return int(response["p"]), int(response["g"]), int(response["y"])

def send_encrypted_message(c1: bytes, c2: bytes):
    response = run_command({"command": "encrypted_command",
                            "encrypted_command": {
                                "c1": c1.hex(),
                                "c2": c2.hex()
                            }})
    encrypted_res = response["encrypted_res"]
    return bytes.fromhex(encrypted_res["c1"]), bytes.fromhex(encrypted_res["c2"])

def set_response_key(p: int, g: int, y: int):
    response = run_command({"command": "set_response_key",
                            "p": str(p),
                            "g": str(g),
                            "y": str(y)})
    return response["res"]

own_elgamal_key = ElGamal.generate(256, os.urandom)
set_response_key(own_elgamal_key.p, own_elgamal_key.g, own_elgamal_key.y)
elgamal_key = ElGamal.construct(get_public_key())
encrypted_command = ElGamalImpl.encrypt(elgamal_key, b'backdoor')
encrypted_response = send_encrypted_message(encrypted_command[0], encrypted_command[1])
ptxt = ElGamalImpl.decrypt(own_elgamal_key, encrypted_response[0], encrypted_response[1])
print(ptxt)
