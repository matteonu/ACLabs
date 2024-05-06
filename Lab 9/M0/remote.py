import json
import secrets
import socket
from string import printable

ALPHABET = printable

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50900

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================

p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
g = 35347793643784512578718068065261632028252678562130034899045619683131463682036436695569758375859127938206775417680940187580286209291486550218618469437205684892134361929336232961347809792699253935296478773945271149688582261042870357673264003202130096731026762451660209208886854748484875573768029653723060009335

fd = socket.create_connection(
    (HOST if REMOTE else "localhost", PORT)).makefile("rw")


def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def get_alice_key() -> int:
    response = run_command({"command": "alice_initialisation"})
    return response["alice_key"], response["resp"]

def get_bob_key(alice_key: int, alice_message: str):
    response = run_command({"command": "bob_initialisation", 
                            "alice_hello": {
                                "resp": alice_message,
                                "alice_key": alice_key
                            }})
    return response["bob_key"], response["resp"]

def finish_alice(bob_key: int, bob_message: str):
    response = run_command({"command": "alice_finished",
                            "bob_hello": {
                                "resp": bob_message,
                                "bob_key": bob_key
                            }})
    print(response)
    return bytes.fromhex(response["encrypted_flag"]), bytes.fromhex(response["nonce"])

alice_key, alice_message = get_alice_key()
bob_public, bob_message = get_bob_key(1, alice_message)
encrypted_flag, nonce = finish_alice(1, bob_message)
shared_bytes = int(1).to_bytes(int(1).bit_length(), 'big')
secure_key = HKDF(master = shared_bytes, key_len = 32, salt = b'Secure alice and bob protocol', hashmod = SHA512, num_keys = 1)
cipher = AES.new(secure_key, AES.MODE_CTR, nonce=nonce)
print(cipher.decrypt(encrypted_flag))


