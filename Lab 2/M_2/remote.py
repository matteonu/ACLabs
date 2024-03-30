#!/usr/bin/env python3

import json
import socket
from Crypto.Util.Padding import pad

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50220

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


padded_message = pad(str.encode("flag, please!"), 16)
res = run_command({"command": "encrypt",
                   "prepend_pad": padded_message.hex()})['res']
encrypted_message = res[:32]
print(run_command({"command": "solve",
                   "ciphertext": encrypted_message}))
