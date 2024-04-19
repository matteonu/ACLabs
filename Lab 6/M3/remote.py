from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256
from tqdm import tqdm

ALPHABET = ascii_letters + digits



# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50603

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
        'command':'corrupt'
    })
    key = bytes.fromhex(response['res'][-32:])

    result = {}
    combinations = itertools.product(ALPHABET, repeat=4)
    combinations = tqdm(combinations ,total=len(ALPHABET) ** 4)
    for combination in combinations:
        candidate_str = ''.join(combination)
        result[HMAC.new(key = key, msg=candidate_str.encode(), digestmod=SHA256).hexdigest()] = candidate_str
    return result

hashdict = build_dict()


for _ in range(128):
    response = run_command({
        'command':'challenge'
    })
    HASH = response['res'][-64:]
    candidate = hashdict[HASH]

    response = run_command({
        'command': 'guess',
        'guess': candidate
    })


response = run_command({
    'command': 'flag',
})

print(response)

