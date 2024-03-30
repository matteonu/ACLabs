from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits
import secrets



# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50501

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

response = run_command({
    'command':'password'
})

password = bytes.fromhex(response['res'])
print(password)

password_hash = argon2.hash(password)
response = run_command({
    'command': 'guess',
    'guess':password_hash
})
print(response)