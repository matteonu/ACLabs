#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50301)


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

intro_encrypted = bytes.fromhex(response['res'][-32:])
intro_plaintext = pad(b'intro', 16)
flag_plaintext = pad(b'flag', 16)
command = xor(intro_encrypted, xor(intro_plaintext, flag_plaintext))

print(intro_encrypted)
request = {
    "command": "encrypted_command",
    "encrypted_command": command.hex()
}
json_send(request)
response = json_recv()
print(response)
