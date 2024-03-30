import secrets
import random
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

MESSAGES = [
    "Pad to the left",
    "Unpad it back now y'all",
    "Game hop this time",
    "Real world, let's stomp!",
    "Random world, let's stomp!",
    "AES real smooth~"
]

# Pad all the messages to 32 bytes so that they are all at the same length
MESSAGES = [
    msg.ljust(32) for msg in MESSAGES
]

# Guess correctly 64 times to get the flag!
TARGET_SCORE = 64


class FunkyServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)
        self.score = 0

        # Securely initialize randomness using the secrets library

        random.seed(secrets.choice(MESSAGES))

        super().__init__(*args, **kwargs)

    @on_startup()
    def init_round(self):
        self.secret_message = secrets.choice(MESSAGES)

    @on_command("encrypt")
    def handle_encrypt(self, msg):
        try:
            ptxt = bytes.fromhex(msg["msg"]) + self.secret_message.encode()
            iv = random.randbytes(16)
            padded_ptxt = pad(ptxt, 16)
            ptxt_blocks = [padded_ptxt[i:i+16]
                           for i in range(0, len(padded_ptxt), 16)]
            print(ptxt_blocks)

            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)

            ctxt = cipher.encrypt(pad(ptxt, 16))

            self.send_message(
                {"ctxt": ctxt.hex(), "iv": iv.hex()}
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("guess")
    def handle_guess(self, msg):
        try:
            guess = msg["guess"]
            if guess == self.secret_message:
                self.score += 1
                self.send_message(
                    {"result": f"Funky! ({self.score}/{TARGET_SCORE})"})
                self.init_round()
            else:
                self.send_message({"error": "Peace out!"})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        if self.score >= TARGET_SCORE:
            self.send_message({"flag": self.flag})
        else:
            self.send_message({"error": "Not funky enough yet!"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    FunkyServer.start_server("0.0.0.0", 50402, flag=flag)
