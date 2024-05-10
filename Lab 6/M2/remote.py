#!/usr/bin/env python3

import json
import socket
import subprocess
from server.shazam import SHAzam

PORT = 50602
REMOTE = True
HOST = "aclabs.ethz.ch"

BLOCK_SIZE_BYTES = 64
WORD_SIZE_BYTES = 4
LONG_SIZE_BYTES = 8

fd = socket.create_connection((HOST if REMOTE else "localhost", PORT)).makefile("rw")
def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def get_padding(input: bytes, original_message_length: int):
        message_bit_length = 8 * original_message_length
        padding = get_zero_padding(message_bit_length)
        encoded_length = int(message_bit_length).to_bytes(length=8, byteorder='big')
        last_blocks = bitstring_to_bytes(padding).__add__(encoded_length)
        return last_blocks

def get_zero_padding(message_bit_length):
    zero_padding_length = 447 - message_bit_length
    if zero_padding_length < 0:
        zero_padding_length += 512
    padding = '1' + zero_padding_length * '0'
    return padding

def extend_message(message_to_pad: bytes, extension: bytes, original_tag: bytes) -> tuple[bytes, bytes]:
    extended_message = get_extended_message(message_to_pad, extension)
    forged_tag = compute_tag(extension, original_tag)
    return (extended_message, forged_tag)

def compute_tag(extension, original_tag):
    sha = initialize_shazam(original_tag)
    sha.update(extension)
    forged_tag = sha.digest()
    return forged_tag

def initialize_shazam(original_tag):
    sha = SHAzam()
    hash_state = [original_tag[i:i+WORD_SIZE_BYTES]
                           for i in range(0, len(original_tag), WORD_SIZE_BYTES)]
    hash_state = [int.from_bytes(byte_array) for byte_array in hash_state]
    sha.hash = hash_state
    sha.length = 1
    return sha

def get_extended_message(message_to_pad, extension):
    original_length = len(message_to_pad) + 16 # message + key length
    padding = get_padding(message_to_pad, original_length)
    padded_message = message_to_pad.__add__(padding)
    extended_message = padded_message.__add__(extension)
    return extended_message

def get_message_tag_pair(run_command):
    response = run_command({
    "command": "get_token"
    })
    command_string = bytes.fromhex(response['authenticated_command'])
    mac = bytes.fromhex(response['mac'])
    return command_string,mac

command_string, mac = get_message_tag_pair(run_command)
new_message, new_tag = extend_message(command_string, b"&command=flag", mac)
response = run_command({
    "command": "authenticated_command",
    "authenticated_command":  new_message.hex(),
    "mac": new_tag.hex()
})

print(response)
