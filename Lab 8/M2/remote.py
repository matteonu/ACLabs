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





# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50802

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

def decrypt_ciphertext(c:int) -> bytes:
    response = run_command({"command" : "decrypt", "ciphertext":long_to_bytes(c).hex()})
    if "error" in response:
        raise ValueError(response["error"])
    return bytes_to_long(bytes.fromhex(response["res"]))

def get_encrypted_flag() -> int:
    response = run_command({"command": "encrypted_flag"})
    return response

def exact_int_root(radicand, k):
    ''' Computes the int root such that root ** k == radicand and root == None if this doesn't exist
    
    >>> exact_int_root(9, 3)
    >>> exact_int_root(64, 3)
    4
    >>> exact_int_root(16269, 27743)
    >>> exact_int_root(163956, 30674)
    >>> exact_int_root(8, 3)
    2
    '''
        
    if radicand < 0 or k < 0:
        raise ValueError('exact_int_root is undefined for negative numbers')
    
    if k == 0:
        raise ValueError('exact_int_root is undefined for k == 0 (1/k == 1/0)')

    
    # The following are needed to make sure that root < radicand
    # otherwise upper_bound = radicand causes an error

    if radicand in (0, 1):
        return radicand
    elif k == 1:
        return radicand
    
    # test if k is too big to enable any solution
    # Not required, but it can speed up silly cases
    if k >= radicand or 2 ** k > radicand:
        return None
    
    # Can improve by finding a better approximation but you have to be cautious
    # That you always make sure the approximation fulfills
    # lower_bound <= root < upper_bound
    lower_bound = 0
    upper_bound = radicand

    # Binary search for root
    root_guess = (lower_bound + upper_bound) // 2
    while upper_bound - lower_bound > 0:
        radicand_guess = root_guess ** k
        
        if radicand_guess < radicand:
            # add 1 because lower_bound should be the smallest *possible* guess for root
            # and we just ruled out root_guess.
            lower_bound = root_guess + 1
        elif radicand_guess == radicand:
            return root_guess
        else:
            upper_bound = root_guess
        
        root_guess = (lower_bound + upper_bound) // 2
    # No more valid guesses exist
    return None

encrypted_flag = get_encrypted_flag()
print(encrypted_flag) 
encrypted_flag = get_encrypted_flag()
print(encrypted_flag) 
ctxt = int(encrypted_flag["ctxt"])
cubic_root = exact_int_root(ctxt, 3)
print('ctxt', ctxt)
print('cubic_root', cubic_root)
print('cubic_root**3', cubic_root**3)
print('difference', ctxt - cubic_root**3)
assert pow(cubic_root, 3) == ctxt
print(long_to_bytes(cubic_root))

