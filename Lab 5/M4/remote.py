from passlib.hash import argon2
import json
import socket
from string import ascii_lowercase
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256
from tqdm import tqdm




# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50504

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

def build_dict():
    response = run_command({
        'command':'salt'
    })

    SALT = bytes.fromhex(response['salt'])
    result = {}
    combinations = itertools.product(ascii_lowercase, repeat=5)
    combinations = tqdm(combinations ,total=26**5)
    for combination in combinations:
        candidate_str = ''.join(combination)
        result[HMAC.new(key = SALT, msg=candidate_str.encode(), digestmod=SHA256).hexdigest()] = candidate_str

    return result

hashdict = build_dict()


for _ in range(5):
    response = run_command({
        'command':'password'
    })

    HASH = response['pw_hash']

    candidate = hashdict[HASH]

    response = run_command({
        'command': 'guess',
        'password': candidate
    })


response = run_command({
    'command': 'flag',
})

print(response)

