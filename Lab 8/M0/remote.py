from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits, printable
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256
from rsa import rsa_key_gen, rsa_enc, rsa_dec
ALPHABET = printable



# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50800

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

def set_parameters(N:int, e:int, d:int, p:int, q:int) -> bytes:
        print(run_command({
            "command": "set_parameters",
            "N": N,
            "e": e,
            "d": d,
            "p": p,
            "q": q
        }))

def get_encrypted_flag() -> int:
    response = run_command({"command": "encrypted_flag"})
    print(response)
    return response["res"].split(": ")[1]

parameters = rsa_key_gen()
set_parameters(parameters[0][0], parameters[0][1], parameters[1][1], parameters[2][0], parameters[2][1])
encrypted_flag = get_encrypted_flag()
decrypted_flag = rsa_dec(parameters[1], int(encrypted_flag))
print(decrypted_flag.to_bytes((decrypted_flag.bit_length() + 7) // 8, "big").decode())       