#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class PaddingOracle(CommandServer):
    """ PaddingOracle implements a byte recovery game challenger.

    The challenger interacts with an adversary, and reveals a flag to the
    adversary if they show a significant advantage in guessing the last byte of the challenge.
    """

    def __init__(self, key, flag, *args, **kwargs):
        self.flag = flag
        self.rounds = 100
        self.guesses = 0

        self.block_size = 16
        self.k = key

        self.challenge = None

        super().__init__(*args, **kwargs)

    def send_encrypted_message(self, msg):
        cipher = AES.new(self.k, AES.MODE_CBC)
        ctxt = cipher.encrypt(pad(msg.encode(), self.block_size))
        encrypted_res = cipher.iv + msg.encode()
        self.send_message({"res": encrypted_res.hex()})

    @on_command("decrypt")
    def decrypt_handler(self, msg):
        try:
            ciphertext = bytes.fromhex(msg["ciphertext"])
            iv = ciphertext[:self.block_size]
            ctxt = ciphertext[self.block_size:]

            cipher = AES.new(self.k, AES.MODE_CBC, iv=iv)
            decrypted_ptxt = cipher.decrypt(ctxt)
            print("decrypted_ptxt: " + decrypted_ptxt.decode())
            unpadded_ptxt_encoded = unpad(
                decrypted_ptxt, self.block_size)
            print("unpadding successful")
            plaintext = unpadded_ptxt_encoded.decode()

            self.send_encrypted_message("Hello!")
        except (KeyError, ValueError) as e:
            self.send_encrypted_message(repr(e))

    @on_command("challenge")
    def challenge_handler(self, msg):
        print("hellohello")
        self.challenge = secrets.token_bytes(8).hex()

        cipher = AES.new(self.k, AES.MODE_CBC)
        print(cipher.block_size)
        ctxt = cipher.encrypt(self.challenge.encode())
        print("challenge length " + str(len(self.challenge)))
        print("encoded challenge length " + str(len(self.challenge.encode())))
        print("ctext length " + str(len(ctxt)))

        encrypted_challenge = cipher.iv + ctxt
        print(encrypted_challenge)

        self.send_message({"res": encrypted_challenge.hex()})

    @on_command("guess")
    def guess_handler(self, msg):
        challenge_char_guess = msg["guess"]
        print("guess: " + challenge_char_guess +
              "| length = " + str(len(challenge_char_guess)))
        print("actual char: " +
              self.challenge[-1] + "| length = " + str(len(self.challenge[-1])))
        print("challenge: " + self.challenge)
        if self.challenge[-1] != challenge_char_guess or self.challenge is None:
            self.send_message({"res": "You lost"})
            self.close_connection()
            return

        self.guesses += 1
        self.send_message(
            {"res": f"You won round {self.guesses}/{self.rounds}!"})
        self.challenge = None

    @on_command("flag")
    def flag_handler(self, msg):
        if self.guesses < self.rounds:
            self.send_message({"res": "Not enough guesses!"})
            self.close_connection()
            return

        self.send_message({"res": self.flag})
        self.close_connection()


if __name__ == "__main__":
    key = secrets.token_bytes(16)
    flag = 'flag{test_flag}'
    PaddingOracle.start_server("localhost", 50341, key=key, flag=flag)
