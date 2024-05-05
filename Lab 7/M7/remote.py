from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits, printable
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256

ALPHABET = printable

BLOCK_SIZE = 16



# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50707

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


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))

def pad(self, pt: bytes):
    """Return padded plaintext"""
    padding_number = 16 - len(pt)%self.block_len
    padding = padding_number * padding_number.to_bytes()
    print(padding)

    return pt.__add__(padding)

def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def get_token() -> bytes:
    response = run_command({
            "command": "get_token"
        })
    return bytes.fromhex(response["guest token"])

def show_state():
    response = run_command({
        'command': 'show_state',
        'prefix': ''
    })
    return response["resp"]

def is_valid_token(token:bytes):
    response = run_command({
            "command": "authenticate",
            "token" : token.hex()
        })
    return "resp" in response and response["resp"] == "ok"

def rekey(key: bytes):
    run_command({
    'command':"rekey",
    'key': key.__add__(bytes(24 * [0])).hex()
})


token = get_token()
found_key = False
while True:
    key = secrets.token_bytes(32)
    rekey(key)
    if is_valid_token(token):
        break

print(show_state())





# print(token)
# print(len(token))
# iv = token[:BLOCK_SIZE]
# c = token[BLOCK_SIZE:BLOCK_SIZE*2]
# tag = token[BLOCK_SIZE*2:]
# forged_IV = xor(xor(pad(b'guest'), pad(b'admin')), pad(iv))
# ctxt = forged_IV.__add__(c)


print(rekey(run_command))
