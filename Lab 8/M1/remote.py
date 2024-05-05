from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits, printable
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256
ALPHABET = printable
from Crypto.Util.number import bytes_to_long, long_to_bytes




# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50801

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================


BLOCK_SIZE = 16

fd = socket.create_connection(
    (HOST if REMOTE else "localhost", PORT)).makefile("rw")


def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def decrypt_ciphertext(c:int) -> bytes:
    response = run_command({"command" : "decrypt", "ciphertext":long_to_bytes(c).hex()})
    if "error" in response:
        raise ValueError(response["error"])
    return bytes_to_long(bytes.fromhex(response["res"]))

def get_encrypted_flag() -> int:
    response = run_command({"command": "encrypted_flag"})
    return response

encrypted_flag = get_encrypted_flag()
print(encrypted_flag)     
encrypted_flag = get_encrypted_flag()
print(encrypted_flag)     
ctxt_int = int(encrypted_flag["encrypted_flag"], 16)
N = int(encrypted_flag["N"], 16)
e = int(encrypted_flag["e"], 16)
forged_ctxt = pow(2, e) * ctxt_int % N
decrypted_forgery = decrypt_ciphertext(forged_ctxt)
print(long_to_bytes(decrypted_forgery//2))

