import json
import socket
from string import ascii_letters, digits


ALPHABET = ascii_letters + digits
# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50404

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


BLOCK_SIZE = 16


def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))


def get_file_id():
    response = run_command({
        "command": "list",
        "user": "admin"
    })
    file_id = bytes.fromhex(response["result"][0])
    return file_id

def get_file(ctxt):
    response = run_command({
        "command": "get",
        "user": "admin",
        "ctxt": ctxt.hex()
    })
    return response['result']

def is_valid_padding(ctxt: bytes) -> bool:
    response = run_command({
                "command": "get",
                "user": "admin",
                "ctxt": ctxt.hex()
            })
    return 'File not found!' in response['error']

def get_flag(secret):
    response = run_command({
        "command": "flag",
        "solve": secret,
    })
    
    if 'flag' in response:
        print(response['flag'])

def make_guess(encryption, message):
    file_id = get_file_id()
    padded_file_id = bytes([1]).__add__(file_id)
    forged_iv = xor(encryption, padded_file_id)
    secret = get_file(forged_iv.__add__(message)) 
    get_flag(secret)

"""
Observation: The server returns the error "File not found!" if we send a "get" query as admin with an encryption
of a message with a valid padding. This means that we can use the server as a padding oracle. Therefore we can
perform an attack similar to the BEAST-attack
"""

for round in range(40):
    encryption = b''
    message = bytes(16*[0])
    for i in range(1, 17):
        for candidate_byte in range(256):
            iv = encryption.__add__(bytes([candidate_byte] + (16 - i) * [0]))
            if is_valid_padding(iv.__add__(message)):
                # edge-case-check for the case where we accidentaly hit a 0 that is followed by a sequence of 
                # bytes of the form [0^n | 1] resulting in a legal padding. In this case we xor the byte following
                # the candidate byte with 2 such that we get a byte that is not 0 or one. if the byte decrypts again 
                # to a legal padding, we hit a 1.
                if i < 16:
                    iv = encryption.__add__(
                        bytes([(candidate_byte) % 256] + [2] + (16 - i - 1) * [0]))
                    if not is_valid_padding(iv.__add__(message)):
                        continue

                current_encryption_byte = xor(bytes([candidate_byte]), bytes([1]))
                encryption = encryption.__add__(current_encryption_byte)
                break
    
    make_guess(encryption, message)
