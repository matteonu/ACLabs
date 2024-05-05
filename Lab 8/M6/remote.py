import datetime
import time
from passlib.hash import argon2
import json
import socket
from string import ascii_letters, digits, printable
import secrets
import itertools
from Crypto.Hash import HMAC, SHA256
ALPHABET = printable
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util import number
import math
import numpy as np 
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA





# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50806

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

def generate_key() -> int:
    response = run_command({"command": "generate"})
    N = response["N"]
    e = response["e"]
    key_index = response["key_index"]
    return N, e, key_index

def get_encryption(index: int) -> int:
    response = run_command({"command": "encrypt", "index": index})
    return bytes_to_long(bytes.fromhex(response["encrypted_flag"]))

def make_random_stream(seed: int):
    """Use Numpy to generate a random stream from a specific seed. 
    Because I multiply it by 16 random bytes this must be secure."""
    np.random.seed(seed)
    return lambda n: np.random.bytes(n)

def get_p(time_seed: int):
    p = number.getPrime(1024, randfunc=make_random_stream(time_seed))
    return p

t = datetime.datetime.now().second
while t != 0:
    t = datetime.datetime.now().second
N, e, key_index = generate_key()
p = get_p(0)
q = N//p
phiN = (p-1)*(q-1)
d = number.inverse(e, phiN)
rsa = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(rsa)
ctxt = get_encryption(0)
m = cipher.decrypt(long_to_bytes(ctxt))
print(m)


