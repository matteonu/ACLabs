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
PORT = 50505

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change this to graded.aclabs.ethz.ch if you use this for graded labs
HOST = "aclabs.ethz.ch"

# =====================================================================================
#   Client Boilerplate (Do not touch, do not look)
# =====================================================================================


BLOCK_SIZE = 16

def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))

fd = socket.create_connection(
    (HOST if REMOTE else "localhost", PORT)).makefile("rw")

m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
recipe = b"Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]"
original_token = b"username:admin&m1:" + m1 + b"&fav_food_recipe:" + recipe

forged_m1 = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
forged_m2 = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")

pad = b"username:admin&m1:" + forged_m1 + b"&fav_food_recipe:" + recipe[: -len(forged_m1)]

def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

response = run_command({
    'command' : 'token'
})

print(response)

token_enc = bytes.fromhex(response['token_enc'])
nonce = response['nonce']
forged_token_enc = xor(token_enc, xor(pad, original_token))

response = run_command({
    'command' : 'login',
    'token_enc' : forged_token_enc.hex(),
    'nonce' : nonce,
    'm2': forged_m2.hex()
})

print(response)

print(run_command({
    'command' : 'flag'
}))

