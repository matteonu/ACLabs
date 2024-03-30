import secrets
from string import ascii_letters
from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def xor(x: bytes, y: bytes):
    return bytes(a ^ b for a, b in zip(x, y))


def generate_secret() -> str:
    return ''.join(secrets.choice(ascii_letters) for _ in range(16))


class MissCounter:
    """ Hey Miss CTR can I make beauty stay if I roll my cipher? """

    def __init__(self, key: bytes, initial_counter: int) -> None:
        if len(key) != 16:
            raise ValueError("Wrong key size")

        self.key = key
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.counter = initial_counter

    def encrypt(self, msg: bytes) -> bytes:
        if len(msg) > 1024:
            raise ValueError("How about you don't?")

        msg_blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), 16)]
        print(msg_blocks)
        ctxt_blocks = []

        for msg_block in msg_blocks:
            # if self.counter overflows, this will raise an exception
            # (so don't even try)
            print(self.counter)
            keystream_block = self.aes.encrypt(
                self.counter.to_bytes(BLOCK_SIZE, "big"))
            ctxt_block = xor(keystream_block, msg_block)
            ctxt_blocks.append(ctxt_block)
            self.counter += 1

        return b''.join(ctxt_blocks)

    def decrypt(self, ctxt) -> bytes:
        raise NotImplementedError("They don't pay me enough to implement this")


class MissCountingServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)
        self.secret_message = generate_secret()

        self.counter = int.from_bytes(secrets.token_bytes(BLOCK_SIZE), "big")
        self.flag_attempts = 0

        super().__init__(*args, **kwargs)

    def encrypt_string(self, message: str):
        cipher = MissCounter(self.key, self.counter)
        ctxt = cipher.encrypt(message.encode())

        # Update the counter
        len_msg = len(message)
        print(message)
        print("message length: " + str(len_msg))
        print('increased counter by ' + str(len_msg//BLOCK_SIZE))
        self.counter += len_msg // BLOCK_SIZE
        print(self.counter)
        return ctxt

    @on_command("encrypt")
    def handle_encrypt(self, msg):
        """ Encrypt your message """

        try:
            ptxt = msg["msg"]
            ctxt = self.encrypt_string(ptxt)
            self.send_message({"result": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("encrypt_secret")
    def handle_encrypt_secret(self, msg):
        """ Encrypt my secret message """

        try:
            secret_msg = f'Secret: {self.secret_message}. Bye!'
            print(secret_msg)
            ctxt = self.encrypt_string(secret_msg)
            self.send_message({"result": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            if self.flag_attempts >= 1000:
                self.send_message(
                    {"error": "I kept count of your attempts... and you've done too many"})
                self.close_connection()
            else:
                if msg["solve"] == self.secret_message:
                    self.send_message({"flag": self.flag})
                    self.close_connection()
                else:
                    self.send_message({"error": "Naah."})
                    self.flag_attempts += 1

        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    MissCountingServer.start_server("0.0.0.0", 50400, flag=flag)
