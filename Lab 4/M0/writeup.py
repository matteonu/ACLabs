#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

tn = telnetlib.Telnet("aclabs.ethz.ch", 50400)

def xor(X, Y):
    assert (len(X) == len(Y))
    return bytes(x ^ y for (x, y) in zip(X, Y))


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def get_encrypted_secret():
    request = {
        "command": "encrypt_secret"
    }
    json_send(request)

    response = json_recv()

    encrypted_secret = bytes.fromhex(response['result'])
    return encrypted_secret


def get_message_encryption(ptxt):
    request = {
        "command": "encrypt",
        "msg": ptxt
    }

    json_send(request)
    response = json_recv()
    return response['result']


"""
Idea: The server does not increase the counter correctly if the message is shorter than the 
block-length. Therefore we can retrieve the first 15 bytes of the encryption of the counter 
and use it to get part of the secret.
"""


BLOCK_SIZE = 16
ptxt = 15*'0'

# get the first 15 bytes of the encryption of the counter
response = get_message_encryption(ptxt)
otp0 = xor(ptxt.encode(), bytes.fromhex(response))

# get the encryption of the secret. The first half was encrypted by xoring the plaintext with otp0.
encrypted_secret = get_encrypted_secret()
encrypted_secret0 = encrypted_secret[:15]
encrypted_secret1 = encrypted_secret[16:]


# After the secret was encrypted the counter was not increased, since the length of the secret is 
# not a multiple of the block length.
response = get_message_encryption(ptxt)
otp1 = xor(ptxt.encode(), bytes.fromhex(response))


# with the encryptions of the two counter values we can decrypt the secret except for one byte.
decrypted_secret0 = xor(encrypted_secret0, otp0)
decrypted_secret1 = xor(encrypted_secret1, otp1[:-1])
decrypted_secret0 = decrypted_secret0[len('Secret: '):].decode()
decrypted_secret1 = decrypted_secret1[:-len('. Bye!')].decode()

# brute force the missing plaintext byte.
for i in range(256):
    secret = decrypted_secret0 + chr(i) + decrypted_secret1
    request = {
        "command": "flag",
        "solve": secret
    }
    json_send(request)
    response = json_recv()
    if 'flag' in response.keys():
        print(response['flag'])
        break
