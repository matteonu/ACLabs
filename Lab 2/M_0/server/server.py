#!/usr/bin/env python3

"""
This is a simple server that will help introduce you to our framework

The server runs on our machines (reachable at aclabs.ethz.ch) and listens on the port
defined below (line 56) on a TCP socket. As soon as you connect, it will listen for
JSON-formatted messages.

To send the `intro` command, send the following string to the server:

{"command": "intro"}

Additional parameters can be provided as well:

{"command": "intro", "name": "Duke"}

This server is structured so that you can also run it locally.
Simply run: `python server.py`. Now you will also have an instance of the server
running on your local system (Reachable on "localhost", port 50200). Of course, the
*real* flag is the one stored on our server, but this will help you in debugging your attacks.
"""

from boilerplate import CommandServer, on_command


class Server(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        super().__init__(*args, **kwargs)

    @on_command("intro")
    def intro_handler(self, msg):
        if "name" in msg:
            self.send_message(
                {
                    "res": f"Welcome to the oracle, {msg['name']}! The \"flag\" command will give you the flag!"
                }
            )
        else:
            self.send_message(
                {
                    "res": 'Welcome to the oracle! The "flag" command will give you the flag!'
                }
            )

    @on_command("flag")
    def flag_handler(self, msg):
        if "token" not in msg:
            self.send_message({"res": "No token, no flag"})
            return

        token = msg["token"]

        if token == "534554454320415354524f4e4f4d59":
            self.send_message({"flag": self.flag})
        else:
            self.send_message({"res": "Mhh... that doesn't look right"})


if __name__ == "__main__":
    # The real flag is different and stored in our server instance
    Server.start_server("0.0.0.0", 50200, flag="flag{this_is_a_test_flag}")
