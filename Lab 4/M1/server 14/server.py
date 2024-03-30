import secrets
from string import ascii_letters
from boilerplate import CommandServer, on_command

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))


def generate_secret() -> str:
    return ''.join(secrets.choice(ascii_letters) for _ in range(16))


class UnchainedServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        key = secrets.token_bytes(16)
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.secret_message = generate_secret()

        super().__init__(*args, **kwargs)

    @on_command("encrypt")
    def handle_encrypt(self, msg):
        """"""
        try:
            user_ptxt = bytes.fromhex(msg["msg"])
            ptxt = user_ptxt + self.secret_message.encode()
            ptxt = pad(ptxt, BLOCK_SIZE)

            ptxt_blocks = [ptxt[i:i+BLOCK_SIZE]
                           for i in range(0, len(ptxt), BLOCK_SIZE)]
            print(ptxt_blocks)
            iv = secrets.token_bytes(BLOCK_SIZE)
            prev_block = iv

            ctxt_blocks = [iv]

            for block in ptxt_blocks:
                cipher_in = xor(block, prev_block)
                cipher_out = self.cipher.encrypt(cipher_in)
                ctxt_blocks.append(cipher_out)
                prev_block = cipher_in

            ctxt = b''.join(ctxt_blocks)

            self.send_message({"result": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            solve = msg["solve"]

            if solve == self.secret_message:
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"error": "Naah."})

            self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    UnchainedServer.start_server("0.0.0.0", 50401, flag=flag)
