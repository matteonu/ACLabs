#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50302)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


prefix = pad(b'', 15)

for i in range(256):
    message = prefix.__add__(bytes([i]))
    request = {
        "command": "encrypted_command",
        "encrypted_command": message.hex()
    }
    json_send(request)

    response = json_recv()['res']
    if 'Failed' not in response:
        decryption = pad(bytes.fromhex(response[-30:]), 16)
        ciphertext = message
        print(decryption)

otp = xor(ciphertext, decryption)

flag_plaintext = pad(b'flag', 16)
command = xor(otp, flag_plaintext)

request = {
    "command": "encrypted_command",
    "encrypted_command": command.hex()
}
json_send(request)
response = json_recv()
print(response)
