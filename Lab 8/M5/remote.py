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
PORT = 50805

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

def gcdExtended(a, b): 
    # Base Case 
    if a == 0 : 
        return b,0,1
             
    gcd,x1,y1 = gcdExtended(b%a, a) 
     
    # Update x and y using results of recursive 
    # call 
    x = y1 - (b//a) * x1 
    y = x1 
     
    return gcd,x,y 

def nextPrime( p: int):
    while True:
        p = p + 2
        if number.isPrime(p):
            return p

def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def get_N() -> int:
    response = run_command({"command": "pub_key"})
    return bytes_to_long(bytes.fromhex(response["N"]))

def get_encryption(e: int) -> int:
    response = run_command({"command": "encrypt", "e": e})
    return bytes_to_long(bytes.fromhex(response["ciphertext"]))
    
N = get_N()
c_1 = 0
e_1 = 3
while True:
    try: 
        c_1 = get_encryption(e_1)
        break
    except:
        e_1 = nextPrime(e_1)
e_2 = nextPrime(e_1)
c_2 = 0
while True:
    try: 
        c_2 = get_encryption(e_2)
        break
    except:
        e_2 = nextPrime(e_2)
        
gcd, a, b = gcdExtended(e_1, e_2)
if a < 0:
    i = number.inverse(c_1, N) % N
    ptxt = (pow(i,-a, N) * pow(c_2, b, N)) % N
elif b < 0:
    i = number.inverse(c_2, N) % N
    ptxt = (pow(c_1, a, N) * pow(i,-b, N)) % N
else:
    ptxt = (pow(c_1, a, N) * pow(c_2, b, N)) % N

print(long_to_bytes(ptxt))