#!/usr/bin/env python3

import json
import socket
from Crypto.Util.Padding import pad
from string import ascii_letters, digits


ALPHABET = ascii_letters + digits
# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50221

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

# ===================================================================================
#    Write Your Solution Below
# ===================================================================================


def build_dict() -> dict:
    result = {}
    for letter in ALPHABET:
        padded_message = pad(str.encode(letter), 16)
        res = run_command({"command": "encrypt",
                           "prepend_pad": padded_message.hex()})['res']
        first_block = res[:32]
        result[first_block] = letter
    return result


def get_last_message_byte() -> str:
    res = run_command({"command": "encrypt",
                       "prepend_pad": ''})['res']
    message_length_without_prepending = len(res)
    for i in range(16):
        padded_message = pad(str.encode(''), i+1)
        res = run_command({"command": "encrypt",
                           "prepend_pad": padded_message.hex()})['res']
        if len(res) > message_length_without_prepending:
            padded_message = pad(str.encode(''), i+2)
            res = run_command({"command": "encrypt",
                               "prepend_pad": padded_message.hex()})['res']
            return res[-32:]


for i in range(5):
    cipher_block_character_mapping = build_dict()
    last_message_byte = get_last_message_byte()
    """ print(last_message_byte)
    print(cipher_block_character_mapping) """
    if last_message_byte in cipher_block_character_mapping.keys():
        res = run_command({
            "command": "solve",
            "solve": cipher_block_character_mapping[last_message_byte]
        })
        print(res)

print(json.loads(fd.readline()))
