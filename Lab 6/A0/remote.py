#!/usr/bin/env python3

import json
import socket

PORT = 50690
REMOTE = True
HOST = "aclabs.ethz.ch"

fd = socket.create_connection((HOST if REMOTE else "localhost", PORT)).makefile("rw")
def run_command(command):
    """Serialize `command` to JSON and send to the server, then deserialize the response"""
    fd.write(json.dumps(command) + "\n")
    fd.flush()
    return json.loads(fd.readline())

response = run_command({
    "command": "hashpump",
    "mac": "05c31528cf681267c35625fc682d8039ff190519b5e349eb07cbb644990987c9",
    "data": "asdf",
    "append": "hjkl",
})

print(bytes.fromhex(response['new_data']))
