import json
import socket
from string import ascii_letters, digits
import secrets


ALPHABET = ascii_letters + digits
# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50405

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


def stupid_pad(msg: bytes):
    """ Pad msg. """
    bit_padding_len = 16 - (len(msg) % 16)
    bit_pading = b"\x00" * (bit_padding_len - 1) + b"\x01"
    return bit_pading + msg


def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))

def get_encryption(msg: str):
    response = run_command({"command": "encrypt",
                            "msg": msg})
    return response['iv'], response['ctxt']

def get_last_ctxt_block() -> bytes:
    return bytes.fromhex(run_command({
        "command": "list"
    })['result'][0])

def get_flag(secret):
    response = run_command({
        "command": "flag",
        "solve": secret,
    })
    
    if 'flag' in response:
        print(response['flag'])

def decrypts_to_valid_plaintext(ctxt: bytes) -> bool:
    response = run_command({
        "command": "backup",
        "user": "admin",
        "ctxt": ctxt.hex()
    })
    return 'result' in response

def is_correct_start(ctxt_hash: bytes, ctxt_start: bytes):
    return run_command( {
            "command": "check",
            "ctxt_hash": ctxt_hash.hex(),
            "ctxt_start": ctxt_start.hex()
        } )['result']

def get_valid_iv_for_encryption(ctxt: bytes, ptxt: bytes) -> bytes:
    result = b''
    for i in range(1, BLOCK_SIZE + 1):
        for letter in range(256):
            candidate_byte = bytes([letter])
            iv_mask = result.__add__(candidate_byte).__add__( bytes((BLOCK_SIZE - i) * [0]))
            forged_iv = xor(iv_mask, ptxt)
            if decrypts_to_valid_plaintext(forged_iv.__add__(ctxt)):
                if i < BLOCK_SIZE:
                    iv_mask = result.__add__(
                        bytes([(letter) % 256] + [2] + (BLOCK_SIZE - i - 1) * [0]))
                    forged_iv = xor(iv_mask, ptxt)
                    if not decrypts_to_valid_plaintext(forged_iv.__add__(ctxt)):
                        continue

                current_encryption_byte = xor(
                    bytes([letter]), bytes([1]))
                result = result.__add__(current_encryption_byte)
                break
    return result

def get_iv(prefix: bytes, last_ctxt_block: bytes) -> bytes:
    message = prefix + f": don't forget that this is your secret AC login code.".encode() + b" " * 32
    ptxt_blocks = [message[i:i+BLOCK_SIZE]
                    for i in range(0, len(message), BLOCK_SIZE)]
    ptxt_blocks.reverse()
    current_ctxt = last_ctxt_block
    for current_ptxt in ptxt_blocks:
        current_ctxt = get_valid_iv_for_encryption(
            current_ctxt, current_ptxt)
    return current_ctxt

def guess_secret_number():
    last_ctxt_block = get_last_ctxt_block()
    iv = get_iv(bytes(10 * [0]), last_ctxt_block)
    for space in range(1,5):
        for i in range(10**(space-1),10**space):
            padding = bytes([0] * (10 - space - 1) + [1])
            xor_mask = padding + str(i).encode() + bytes((BLOCK_SIZE - space - len(padding)) * [0])
            if is_correct_start(last_ctxt_block, xor(iv, xor_mask)):
                return i

"""
Observation: Similar to M4 we again have a padding oracle, this time with the backup command.
Idea: Again, use the padding oracle to do an attack similar to the BEAST attack to get the IV of a block.
Do this multiple times to get the encryption of the first block. Then guess the number in the first block
of the plaintext to get the correct IV of the whole message.
"""

for round in range(2):
    secret_number = guess_secret_number()
    secret = f"{secret_number}: don't forget that this is your secret AC login code.".encode(
        ) + b" " * 32
    get_flag(secret.hex())
