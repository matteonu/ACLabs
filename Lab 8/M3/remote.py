import json
import socket
from string import printable

ALPHABET = printable
import math

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes

# =====================================================================================
#   Config Variables (Change as needed)
# =====================================================================================

# Remember to change the port if you are reusing this client for other challenges
PORT = 50803

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

def nextPrime(p: int):
    while True:
        p = p - 2
        if number.isPrime(p):
            return p
        
def get_new_prime(p, used_primes, N):
    while True:
        p = number.getPrime(N)
        if p not in used_primes:
            return p

encrypted_flag = {'N': '631497456553705217290047590264481184233596085995856542706769175727415940628448526669930188463384249980494689782275694089516076646497094878789651421848610580405834517333817596798904292754891367252486310773101269038898147851119055077258493638694453635796338149895661227320854202641789620226797594409019319478061537197301225720962210165791110070459221313710737922326505015761345851781371526124149866813894161721387956916237835469159721896656325549020590489808323366970420651347865652396151800656286642188933992644170188902510165524797651079852385761142801869078007215595009662849078430331377574150711684521801813867397494573955990560283666490744192314229847270776703261844397235335429968807378607101424119672546611355878521670784424208180054112202416351006027835319685168907476654325653173026558336147109117375185349384174427324275218720157975035713781859537822951031063108568653565032096036158073941495636318252886200586192651805197162776789769684207217728291420352572804796425222771608196754951635168380273742388956108503284361812877117635002373523351475759915296838151915020310500257552821737676719390807073818567479329851716908198477956079918168267947533708073264676701676465419283721625942766250905442979732217972241927354378448243', 'e': '65537', 'ctxt': '96b56b4dda0efe0e6393872cb738d45190d5b542d946557f0904711b53ed203f477c6ee4851ee6f02d7164f803034977b33afbc37ade10f36800d712775df433d8bb09dde91170587e2ecff357607da6db58c97b777529893aa27aea9319e6bdbdb0ad73e70601eeb03190f9ce073d4d36b6a9e585f39541f590db2a145b33abff571ec23d03072945988b174cbf0873bc06e36967f47cb887689baedb2fb28e2a7847a59927b05e3a83daedee2c3e81e7abd9dbe9c7e66640f7eac21ddc8374d4896d7533a3c56b04c559009fbbdd65806c7facf9bb5007944ddbf1c7ecaecfa85fdddfe20852bb5e2bc640fd28c43342db9dd6fdc6436c6d4569eacae3f22b15bcc27622b93ba8f26a4e5dde8e9a4bd255a0add0ff018ceacd869cfe1e86a0c186759c111243a027faa5b360e0044e627165992822eef64f394f622b319070df1914c6fd7312d18c6e5ec8048832f8b1ec8789f66b9aaad0dae8f8c9b4a9d77c66a0cb3eb09767421c05a77607b63d4a3f49acdc51a21d450ef47414199dd2d452ea6705b438bf239b5105de04ffd18bbc4299c774807cbfba40a145ef09536108fa5beb1b25b424eafeea8db94805af2c3d3b965e2a328d689c679e8cbcc000f943e9d0287d518bec4aa9073e36ebb659801534a8c2d1fffa122f9fbc20eb52bb94f7aee9bfa652135699c4bf1862aeed46d27ed8364b364b2e279de5e039'}
ctxt = int(encrypted_flag["ctxt"], 16)
N = int(encrypted_flag["N"])
e = int(encrypted_flag["e"])

p = math.isqrt(N)
found = False
while not found:
    q = N // p
    if p * q == N:
        found = True
    else:
        p = nextPrime(p)
        print(p)

phiN = (p - 1) * (q - 1)
d = number.inverse(e, phiN)
key = RSA.construct((N, e, d))
cipher = PKCS1_OAEP.new(key)
ptxt = cipher.decrypt(long_to_bytes(ctxt))
print(ptxt)


