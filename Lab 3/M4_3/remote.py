#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import time
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50343)


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


def send_encrypted_command(encrypted_command):
    request = {
        "command": "encrypted_command",
        "encrypted_command": encrypted_command
    }
    json_send(request)
    response = json_recv()['res']
    return response


BLOCK_LENGTH = 16


def get_initial_encryption():
    ciphertext_block = bytes(BLOCK_LENGTH * [0])
    for i in range(256):
        iv = bytes((BLOCK_LENGTH - 1) * [0] + [i])
        ciphertext = iv.__add__(ciphertext_block)
        response = send_encrypted_command(ciphertext.hex())
        if len(response) > 128:
            return (iv, ciphertext_block)


def find_plaintext_byte(suffix: bytes, challenge_cipherblock: bytes, challenge_iv: bytes):
    for i in range(256):
        suffix_length = len(suffix)
        constant_padding_mask = xor(
            pad(b'', suffix_length+1)[:suffix_length], suffix)
        xor_mask = xor(int(i).to_bytes(
            BLOCK_LENGTH - suffix_length, 'big').__add__(constant_padding_mask), challenge_iv)
        response = send_encrypted_command(
            xor_mask.__add__(challenge_cipherblock).hex())
        response_length = len(response)

        if response_length > 128:
            # check if decryption fails with second last byte altered
            try:
                xor_mask = xor(int(i + 256).to_bytes(
                    BLOCK_LENGTH - suffix_length, 'big').__add__(constant_padding_mask), challenge_iv)
                response = send_encrypted_command(
                    xor_mask.__add__(challenge_cipherblock).hex())
                response_length = len(response)
            except:
                pass

            if response_length != 128 or suffix_length == 15:
                padding_byte = int(suffix_length + 1).to_bytes(1, 'big')
                mask_byte = int(i).to_bytes(1, 'big')
                guess_byte = xor(mask_byte, padding_byte)
                return guess_byte


def get_plaintext_block(iv: bytes, ciphertext_block: bytes):
    print("length of cipherblock: " + str(len(ciphertext_block)))
    print("length of iv: " + str(len(iv)))
    assert (len(ciphertext_block) == len(iv))
    plaintext_block = b''
    for byte_idx in range(BLOCK_LENGTH):
        plaintext_block = find_plaintext_byte(
            plaintext_block, ciphertext_block, iv) + plaintext_block
        print(plaintext_block)

    return plaintext_block


def get_plaintext(ciphertext: bytes):
    plaintext = ''
    assert (len(ciphertext) % BLOCK_LENGTH ==
            0 and len(ciphertext) > BLOCK_LENGTH)
    for i in range(int(len(ciphertext)/BLOCK_LENGTH)-1):
        plaintext_block_bytes = get_plaintext_block(
            ciphertext[-(BLOCK_LENGTH * (i + 2)):-(BLOCK_LENGTH * (i + 1))], ciphertext[-(BLOCK_LENGTH * (i + 1)):-(BLOCK_LENGTH * i) if i > 0 else len(ciphertext)])
        plaintext = plaintext_block_bytes.decode() + plaintext
    return plaintext


initial_iv, initial_cipher_block = get_initial_encryption()
ptxt_block = get_plaintext_block(initial_iv, initial_cipher_block)
ptxt_command = pad(b'cd there', BLOCK_LENGTH)
response = send_encrypted_command(
    xor(ptxt_block, xor(initial_iv, ptxt_command)).__add__(initial_cipher_block).hex())
print(get_plaintext(bytes.fromhex(response)))
