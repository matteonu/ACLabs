from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits, printable
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256
from tqdm import tqdm

ALPHABET = printable



# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50604

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

def get_mac_tag(message: str) -> bytes:
    response = run_command({
            "command": "encrypt",
            "ptxt": message
        })
    return bytes.fromhex(response["mac_tag"])

response = run_command({
    'command': 'flag',
})

cipher_text = bytes.fromhex(response['ctxt'])
nonce = bytes.fromhex(response['nonce'])
plaintext = ""

def is_valid_encryption(nonce, cipher_text_fragment, mac_tag):
    response = run_command({
            "command": "decrypt",
            "ctxt" : cipher_text_fragment.hex(),
            "nonce" : nonce.hex(),
            "mac_tag": mac_tag.hex()
        })
    return "success" in response and response["success"]

while (len(plaintext) < len(cipher_text)):
    cipher_text_fragment = cipher_text[:len(plaintext) + 1]
    for character in ALPHABET:
        message = plaintext + character
        assert(len(cipher_text_fragment) == len(message))
        mac_tag = get_mac_tag(message)

        if is_valid_encryption(nonce, cipher_text_fragment, mac_tag):
            plaintext += character
            print(plaintext)
            break

