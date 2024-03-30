#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import time
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50342)


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


BLOCK_LENGTH = 16


def find_plaintext_byte(suffix: bytes, challenge_cipherblock: bytes, challenge_iv: bytes):
    for i in range(256):
        suffix_length = len(suffix)
        constant_padding_mask = xor(
            pad(b'', suffix_length+1)[:suffix_length], suffix)
        xor_mask = xor(int(i).to_bytes(
            BLOCK_LENGTH - suffix_length, 'big').__add__(constant_padding_mask), challenge_iv)
        response = send_decrypt_command(
            xor_mask.__add__(challenge_cipherblock).hex())
        response_length = len(response)

        if response_length == 64:
            # check if decryption fails with second last byte altered
            try:
                xor_mask = xor(int(i + 256).to_bytes(
                    BLOCK_LENGTH - suffix_length, 'big').__add__(constant_padding_mask), challenge_iv)
                response = send_decrypt_command(
                    xor_mask.__add__(challenge_cipherblock).hex())
                response_length = len(response)
            except:
                pass

            if response_length != 128 or suffix_length == 15:
                padding_byte = int(suffix_length + 1).to_bytes(1, 'big')
                mask_byte = int(i).to_bytes(1, 'big')
                guess_byte = xor(mask_byte, padding_byte)
                return guess_byte.decode()


plaintext_block = ''
for round in range(10):
    request = {"command": "challenge"}
    json_send(request)
    response = json_recv()['res']
    challenge_cipherblock = bytes.fromhex(response[-32:])
    challenge_iv = bytes.fromhex(response[-64:-32])
    for byte_idx in range(BLOCK_LENGTH):
        plaintext_block = find_plaintext_byte(
            plaintext_block.encode(), challenge_cipherblock, challenge_iv) + plaintext_block
        print(plaintext_block)
    guess_command = {"command": "guess",
                     "guess": plaintext_block}
    json_send(guess_command)
    response = json_recv()['res']
    print(response)
    plaintext_block = ''


flag_command = {"command": "flag"}
json_send(flag_command)
response = json_recv()['res']
print(response)
