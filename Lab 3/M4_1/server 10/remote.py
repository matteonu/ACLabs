#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import time
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50341)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def send_decrypt_command(ciphertext):
    request = {
        "command": "decrypt",
        "ciphertext": ciphertext
    }
    json_send(request)
    response = json_recv()['res']
    return response


for round in range(100):
    request = {"command": "challenge"}
    json_send(request)
    response = json_recv()['res']
    challenge_cipherblock = bytes.fromhex(response[-32:])
    challenge_iv = bytes.fromhex(response[0:32])
    for i in range(256):
        xor_mask = xor(int(i).to_bytes(16, 'big'), challenge_iv)
        response = send_decrypt_command(
            xor_mask.__add__(challenge_cipherblock).hex())
        response_length = len(response)
        if response_length == 64:
            # check if decryption fails with second last byte altered
            xor_mask = xor(int(i + 256).to_bytes(16, 'big'), challenge_iv)
            response = send_decrypt_command(
                xor_mask.__add__(challenge_cipherblock).hex())

            if len(response) != 128:
                padding_byte = int(1).to_bytes(1, 'big')
                mask_byte = int(i).to_bytes(1, 'big')
                guess_byte = xor(mask_byte, padding_byte)
                guess_command = {"command": "guess",
                                 "guess": guess_byte.decode()}
                json_send(guess_command)
                response = json_recv()['res']
                print(response)
                break

flag_command = {"command": "flag"}
json_send(flag_command)
response = json_recv()['res']
print(response)
