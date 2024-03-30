#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50303)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


request = {"command": "howto"}
json_send(request)
response = json_recv()
print(response)


intro_encrypted = bytes.fromhex(response['res'][-32:])
iv = bytes.fromhex(response['res'][-64:-32])
print(iv.hex())
print(intro_encrypted.hex())
intro_plaintext = pad(b'intro', 16)
flag_plaintext = pad(b'flag', 16)
forged_iv = xor(iv, xor(flag_plaintext,  intro_plaintext))

print(intro_encrypted)
request = {
    "command": "encrypted_command",
    "encrypted_command": forged_iv.__add__(intro_encrypted).hex()
}
json_send(request)
response = json_recv()
print(response)
