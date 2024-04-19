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



response = run_command({
    "command": "token"
})
command_string = bytes.fromhex(response['token']['command_string']).decode()
mac = bytes.fromhex(response['token']['mac'])
print(command_string)
print(mac)
append = "&command=flag"
new_hash, new_data = hash_pump(mac.hex(), command_string, append)
print(bytes.fromhex(new_data))

response = run_command({
    "command": "token_command",
    "token": {
        "command_string": new_data,
        "mac": new_hash
    }
})

print(response)
