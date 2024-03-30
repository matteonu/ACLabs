#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import time
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50340)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


prefix = pad(b'', 15)
ciphertext = pad(b'', 16)

for round in range(300):
    print("round " + str(round))
    ciphertext = int(round).to_bytes(16, "big")
    print(ciphertext)
    for i in range(301):
        iv = int(i).to_bytes(16, 'big')
        request = {
            "command": "decrypt",
            "ciphertext": iv.__add__(ciphertext).hex()
        }
        json_send(request)
        response = json_recv()['res']

        if len(response) < 129:
            flag_command = {"command": "guess", "guess": True}
            json_send(flag_command)
            response = json_recv()['res']
            print(response)
            print("winning number: ")
            break

flag_command = {"command": "flag"}
json_send(flag_command)
response = json_recv()['res']
print(response)
