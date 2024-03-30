import json
import socket
from Crypto.Util.Padding import pad
from string import ascii_letters, digits
import random


ALPHABET = ascii_letters + digits
# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50402

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================
MESSAGES = [
    "Pad to the left",
    "Unpad it back now y'all",
    "Game hop this time",
    "Real world, let's stomp!",
    "Random world, let's stomp!",
    "AES real smooth~"
]

MESSAGES = [
    msg.ljust(32) for msg in MESSAGES
]

fd = socket.create_connection(
    (HOST if REMOTE else "localhost", PORT)).makefile("rw")


def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

"""
Observation: The server generates its IV by a random number generator that is initialized with
a random seed from a limited seed-space namely the message space.
Idea: We can just guess the seed (maximum 6 guesses) and with that predict all the IVs for future 
encryptions. Then we can generate a dictionary that maps the block encryption (with the servers key) 
of each message in the message space to the plaintext. For a message we get this block encryption E
by sending the message to the oracle. We get back C = IV xor E. Since we know the IV we can recover E.
With the help of this dictionary we can then guess the ptxt given its encryption.
"""


BLOCK_SIZE = 16


def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))


def get_encryption(msg: str):
    response = run_command({"command": "encrypt",
                            "msg": msg})
    return response['iv'], response['ctxt']


def find_random_seed():
    encryption = get_encryption(b''.hex())
    for message in MESSAGES:
        random.seed(message)
        prediction = random.randbytes(16)
        if prediction.hex() == encryption[0]:
            return message


def get_zero_block_encryption():
    next_iv = random.randbytes(16)
    encryption = get_encryption(
        xor(int(0).to_bytes(16), next_iv).hex())[1][:32]
    return bytes.fromhex(encryption)


def generate_dict():
    cipher_message_dict = {}
    zero_block_encryption = get_zero_block_encryption()
    for message in MESSAGES:
        next_iv = random.randbytes(16)
        encryption = get_encryption(
            xor(xor(message.encode()[:16], next_iv), zero_block_encryption).hex())[1][:32]
        cipher_message_dict[encryption] = message
    return cipher_message_dict


def find_message(ctxt_ptxt_dict):
    for i in range(64):
        next_iv = random.randbytes(16)
        encryption = get_encryption(next_iv.hex())[1][32:64]
        if encryption in ctxt_ptxt_dict.keys():
            run_command({
                "command": "guess",
                "guess": ctxt_ptxt_dict[encryption]
            })


find_random_seed()
ctxt_ptxt_dict = generate_dict()
find_message(ctxt_ptxt_dict)
print(run_command({
    "command": "flag"
})['flag'])
