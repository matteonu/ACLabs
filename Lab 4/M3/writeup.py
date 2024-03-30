import json
import socket
import random

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50403

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


BLOCK_SIZE = 16


def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))

def get_encryption(msg: bytes) -> tuple[bytes]:
    response = run_command({"command": "encrypt",
                            "msg": msg.hex()})
    return bytes.fromhex(response['iv']), bytes.fromhex(response['ctxt'])

def find_random_seed():
    encryption = get_encryption(b'')
    for message in MESSAGES:
        random.seed(message)
        prediction = random.randbytes(BLOCK_SIZE)
        if prediction == encryption[0]:
            return message

def get_zero_block_encryption() -> bytes:
    next_iv = random.randbytes(BLOCK_SIZE)
    encryption = get_encryption(
        xor(int(0).to_bytes(BLOCK_SIZE), next_iv))[1][:BLOCK_SIZE]
    return encryption

def get_block_encryption(msg: bytes) -> bytes:
    assert (len(msg) == BLOCK_SIZE)
    next_iv = random.randbytes(BLOCK_SIZE)
    encryption = get_encryption(
        xor(msg, next_iv))[1][:BLOCK_SIZE]
    return encryption

"""
Idea: Same as in M2 we can predict future IVs. We can get the first byte by first letting the oracle encrypt
0^n. We can then get the block encryption of 0^n under the secret key of the server by xoring with the predicted
IV. Then we query the oracle with the prepend pad [IV xor c' | 0^(n-1)]. The oracle will encrypt 
[IV xor c' | 0^(n-1) p_1 | rest of ptxt] where p_1 is the first plaintext byte. Then we guess the value of p1 by
querying the oracle with [IV xor c' | 0^(n-1) g | rest of ptxt] (g is the guessed byte here) and comparing the 
obtained encryption with the encryption of [IV xor c' | 0^(n-1) p_1 | rest of ptxt]. The other bytes can be guessed
by shifting the plaintext to the left.
"""

ptxt = b''
seed_message = find_random_seed()
current_encrypted_prefix = get_zero_block_encryption().__add__(bytes(BLOCK_SIZE*[0]))
for i in range(1, 2 * BLOCK_SIZE + 1):
    next_iv = random.randbytes(BLOCK_SIZE).__add__(bytes(BLOCK_SIZE*[0]))
    msg = xor(current_encrypted_prefix, next_iv)[:-i]
    encryption = get_encryption(msg)[1]
    c1 = encryption[: BLOCK_SIZE]
    c2 = encryption[BLOCK_SIZE : BLOCK_SIZE * 2]
    for candidate_byte in range(256):
        next_iv = random.randbytes(BLOCK_SIZE)
        truncated_ptxt = ptxt if len(ptxt) <= BLOCK_SIZE - 1 else ptxt[- BLOCK_SIZE + 1:]
        zero_prefix = ((BLOCK_SIZE - i) if i <= BLOCK_SIZE else 0) * [0]
        mask = bytes(zero_prefix).__add__(truncated_ptxt).__add__(bytes([candidate_byte]))
        msg = xor(xor(next_iv, mask), c1)
        encryption = get_encryption(msg)[1][:BLOCK_SIZE]
        if encryption == c2:
            ptxt = ptxt.__add__(bytes([candidate_byte]))
            break
    if i > BLOCK_SIZE:
        shift = i - BLOCK_SIZE
        current_encrypted_prefix = get_block_encryption(
            bytes((BLOCK_SIZE - shift)*[0]).__add__(ptxt[:shift])).__add__(bytes(BLOCK_SIZE*[0]))

response = run_command({
    "command": "guess",
    "guess": ptxt.decode()
})
print(response['flag'])
