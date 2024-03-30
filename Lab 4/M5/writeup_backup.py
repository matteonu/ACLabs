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
REMOTE = False

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "graded.aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================

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


BLOCK_SIZE = 16


def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))


def get_encryption(msg: str):
    response = run_command({"command": "encrypt",
                            "msg": msg})
    return response['iv'], response['ctxt']


message = f"{secrets.randbelow(10000)}: don't forget that this is your secret AC login code.".encode(
) + b" " * 32


def get_last_ctxt_block() -> bytes:
    return bytes.fromhex(run_command({
        "command": "list"
    })['result'][0])


def decrypts_to_valid_plaintext(ctxt: bytes) -> bool:
    response = run_command({
        "command": "backup",
        "user": "admin",
        "ctxt": ctxt.hex()
    })
    return 'result' in response


def is_correct_start(ctxt_hash: bytes, ctxt_start: bytes):
    return run_command(
        {
            "command": "check",
            "ctxt_hash": ctxt_hash.hex(),
            "ctxt_start": ctxt_start.hex()
        }
    )['result']


def get_valid_iv_for_encryption(ctxt: bytes, ptxt: bytes) -> bytes:
    result = b''
    for i in range(1, 17):
        for letter in range(256):
            candidate_byte = bytes([letter])
            iv_mask = result.__add__(candidate_byte).__add__( bytes((16 - i) * [0]))
            forged_iv = xor(iv_mask, ptxt)
            if decrypts_to_valid_plaintext(forged_iv.__add__(ctxt)):
                if i < 16:
                    iv_mask = result.__add__(
                        bytes([(letter) % 256] + [2] + (16 - i - 1) * [0]))
                    forged_iv = xor(iv_mask, ptxt)
                    if not decrypts_to_valid_plaintext(forged_iv.__add__(ctxt)):
                        continue

                current_encryption_byte = xor(
                    bytes([letter]), bytes([1]))
                result = result.__add__(current_encryption_byte)
                break
    return result

def get_iv(prefix: bytes, last_ctxt_block: bytes) -> bytes:
    message = prefix + f": don't forget that this is your secret AC login code.".encode(
    ) + b" " * 32
    message = stupid_pad(message)
    ptxt_blocks = [message[i:i+16]
                    for i in range(0, len(message), 16)]
    ptxt_blocks.reverse()
    current_ctxt = last_ctxt_block
    for current_ptxt in ptxt_blocks:
        current_ctxt = get_valid_iv_for_encryption(
            current_ctxt, current_ptxt)
    return current_ctxt
        

def guess_secret_number():
    last_ctxt_block = get_last_ctxt_block()
    for space in range(1,5):
        iv = get_iv(bytes(space* [0]), last_ctxt_block)
        for i in range(10**(space-1),10**space):
            padding = bytes([0] * (10 - space))
            xor_mask = padding + str(i).encode() + bytes((16 - space - len(padding)) * [0])
            if is_correct_start(last_ctxt_block, xor(iv, xor_mask)):
                return i


for round in range(2):
    secret_number = guess_secret_number()
    secret = f"{secret_number}: don't forget that this is your secret AC login code.".encode(
        ) + b" " * 32
    response = run_command({
        "command": "flag",
        "solve": secret.hex()
    })
print(response)
