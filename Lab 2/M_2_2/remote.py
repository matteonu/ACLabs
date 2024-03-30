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
PORT = 50222

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


def build_dict(suffix: str) -> dict:
    assert (len(suffix) < 16)
    result = {}
    for i in range(256):
        letter = chr(i)
        padded_message = pad(str.encode(letter + suffix), 16).hex()
        res = run_command({"command": "encrypt",
                           "prepend_pad": padded_message})['res']
        first_block = res[:32]
        result[first_block] = letter
    return result

res = run_command({"command": "encrypt",
                   "prepend_pad": ''})['res']
message_byte_length_without_prepending = int(len(res)/2)

def get_plaintext_byte_length():
    for i in range(16):
        padded_message = pad(str.encode(''), i+1)
        res = run_command({"command": "encrypt",
                           "prepend_pad": padded_message.hex()})['res']
        if len(res)/2 > message_byte_length_without_prepending:
            return message_byte_length_without_prepending - (i + 1)

plaintext_byte_length = get_plaintext_byte_length()
probing_block_start = plaintext_byte_length - \
    (plaintext_byte_length % 16) + 16

plaintext = ''
for i in range(plaintext_byte_length):
    plaintext_idx = i + 1
    current_dict = build_dict(plaintext[:15])
    current_shift = 16 - \
        (plaintext_byte_length % 16) + plaintext_idx
    padded_message = pad(str.encode(''), current_shift)
    res = run_command({"command": "encrypt",
                       "prepend_pad": padded_message.hex()})['res']
    probing_block = res[probing_block_start * 2: probing_block_start * 2+32]
    plaintext = current_dict[probing_block] + plaintext


print(plaintext)
