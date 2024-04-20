#!/usr/bin/env python3

import json
import socket
import subprocess

PORT = 50600
REMOTE = True
HOST = "aclabs.ethz.ch"

fd = socket.create_connection((HOST if REMOTE else "localhost", PORT)).makefile("rw")
def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

def hash_pump(mac, data, append):
    port = 50690
    host = "aclabs.ethz.ch"
    fd_hashpump = socket.create_connection((host, port)).makefile("rw")
    command = {
        "command": "hashpump",
        "mac": mac,
        "data": data,
        "append": append,
    }
    fd_hashpump.write(json.dumps(command) + "\n")
    fd_hashpump.flush()
    response = json.loads(fd_hashpump.readline())
    return (response['new_hash'], response['new_data'])

def get_message_and_tag():
    response = run_command({
    "command": "token"
    })
    command_string = bytes.fromhex(response['token']['command_string']).decode()
    mac = bytes.fromhex(response['token']['mac'])
    return command_string, mac

command_string, mac = get_message_and_tag()
new_hash, new_data = hash_pump(mac.hex(), command_string, "&command=flag")
response = run_command({
    "command": "token_command",
    "token": {
        "command_string": new_data,
        "mac": new_hash
    }
})

print(response)
