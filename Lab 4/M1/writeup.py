import json
import socket
from Crypto.Util.Padding import pad
from string import ascii_letters, digits


ALPHABET = ascii_letters + digits
# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50401

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

def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))

def get_encryption(msg: bytes):
    response = run_command({"command": "encrypt",
                            "msg": msg.hex()})
    return response['result']

"""
Observation: In the encryption the currently encrypted block is xored with the accumulated xor of
all the previous plaintext blocks and the IV.
Idea: We send the prepend pad [0^n | 0^(n - 1) g | 0^(n-1)] to the oracle for each guess byte g. 
The oracle will encrypt [0^n | 0^(n - 1) | g | 0^(n-1) | p_1 | rest of ptxt] where p1 is the first 
byte of the plaintext. If we guess the correct byte the xor-sum of the first and third encryption
block will be the same. To get the rest of the bytes we simply shift the plaintext further left by
making the last block of the prepend pad shorter and using the already obtained plaintext bytes in
the second block.
"""


BLOCK_SIZE = 16

ptxt = []
for i in range(1, BLOCK_SIZE + 1):
    for candidate_byte in range(256):
        first_block = bytes(BLOCK_SIZE * [0])
        second_block = bytes((BLOCK_SIZE - i) * [0] + ptxt + [candidate_byte])
        third_block = bytes((BLOCK_SIZE - i) * [0])
        encryption = get_encryption(first_block.__add__(second_block).__add__(third_block))
        encrypted_first_block = encryption[BLOCK_SIZE * 2: BLOCK_SIZE * 4]
        encrypted_third_block = encryption[BLOCK_SIZE * 6: BLOCK_SIZE * 8]
        if (encrypted_first_block == encrypted_third_block):
            ptxt.append(candidate_byte)
            break

print(run_command({
    "command": "flag",
    "solve": bytes(ptxt).decode()
})['flag'])
