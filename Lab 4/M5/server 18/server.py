import secrets
from collections import defaultdict
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES


class YorkshireEncryption:
    """ YorkshireEncryption implement CBC mode with Yorkshire padding. """
    block_size = 16

    @classmethod
    def pad(cls, msg: bytes):
        """ Pad msg. """
        bit_padding_len = cls.block_size - (len(msg) % cls.block_size)
        bit_pading = b"\x00" * (bit_padding_len - 1) + b"\x01"
        return bit_pading + msg

    @classmethod
    def unpad(cls, msg: bytes):
        """ Unpad msg. """
        i = 0
        while msg[i:i+1] == b"\x00":
            i += 1

        if msg[i:i+1] != b"\x01":
            raise ValueError(f"Invalid Padding.")

        return msg[i+1:]

    @classmethod
    def encrypt(cls, key: bytes, msg: bytes) -> bytes:
        """ Encryptin' t'msg usin' CBC method """
        iv = secrets.token_bytes(cls.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ctxt = cipher.encrypt(cls.pad(msg))

        return iv + ctxt

    @classmethod
    def decrypt(cls, key: bytes, msg: bytes) -> bytes:
        """ Decrypt msg under key. """
        iv = msg[:cls.block_size]
        ctxt = msg[cls.block_size:]

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_ptxt = cipher.decrypt(ctxt)
        ptxt = cls.unpad(padded_ptxt)

        return ptxt


class BackupServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.users = dict()
        self.db = defaultdict(bytes)

        self.numsolves = 0
        self.totalsolves = 2

        super().__init__(*args, **kwargs)

    def encrypt(self, user: str, msg: bytes) -> bytes:
        return YorkshireEncryption.encrypt(self.users[user], msg)

    def decrypt(self, user: str, ctxt: str) -> bytes:
        return YorkshireEncryption.decrypt(self.users[user], bytes.fromhex(ctxt))

    @on_startup()
    def place_flag(self):
        """ Store the admin"s secret file! """

        """
        This is equivalent to  calling the "register" command with:
        ```
        {
            "user": "admin",
            "key": secrets.token_bytes(16).hex()
        }
        ```
        """
        self.users["admin"] = secrets.token_bytes(16)

        """
        This is equivalent to calling the backup command with

        ```
        {
            "user": "admin",
            "ctxt": encrypt("admin", secret_file)
        }
        ```
        """
        random_number = secrets.randbelow(10000)
        print(random_number)
        self.secret_file = f"{random_number}: don't forget that this is your secret AC login code.".encode(
        ) + b" " * 32
        file_ctxt = self.encrypt("admin", self.secret_file)
        ctxt_hash = file_ctxt[-16:]
        """ print([x for x in file_ctxt[:16]]) """
        self.db[ctxt_hash] = file_ctxt

    @on_command("register")
    def handle_register(self, msg):
        """ Register new user.

        Given a user and a key, save the user and the key in the user database.
        The key will be used to receive encrypted file backups from the user.
        """

        try:
            user = msg["user"]
            if user in self.users:
                raise ValueError("User already exists")
            key = bytes.fromhex(msg["key"])
            self.users[user] = key
            self.send_message({"result": "ok"})
        except (KeyError, ValueError, TypeError):
            self.send_message({"error": f"Invalid parameters."})

    @on_command("list")
    def handle_list(self, msg):
        """ List backed up files. """

        try:
            self.send_message({"result": list(ctxt_hash.hex()
                              for ctxt_hash in self.db.keys())})
        except (KeyError, ValueError, TypeError):
            self.send_message({"error": f"Invalid parameters."})

    @on_command("backup")
    def handle_backup(self, msg):
        """ Backup a new file for the user.

        Given a user and an encrypted backup file, decrypt the file and save it for the user.
        The file is assumed to be encrypted with the user"s key.
        """

        try:
            user = msg["user"]
            ctxt = msg["ctxt"]

            # With CBC mode encryption, the last block is unique per encrypted file, right?
            ctxt_hash = bytes.fromhex(ctxt)[-16:]

            file = self.decrypt(user, ctxt)

            if ctxt_hash not in self.db:
                self.db[ctxt_hash] = ctxt

            self.send_message({"result": ctxt_hash.hex()})
        except (KeyError, ValueError, TypeError):
            self.send_message({"error": f"Invalid parameters."})

    @on_command("check")
    def handle_check(self, msg):
        """ Check if the encrypted file already exists in the backup.

        This allows for more efficient backups: you don't need to upload a file again if it
        exists already in the server.
        This checks both the first block (`ctxt_start`) and the last block (`ctxt_hash`) of the
        encrypted file, to avoid any possible collision.
        """

        try:
            ctxt_hash = bytes.fromhex(msg["ctxt_hash"])
            ctxt_start = bytes.fromhex(msg["ctxt_start"])
            self.send_message(
                {"result": ctxt_start == self.db[ctxt_hash][:16]})
        except (KeyError, ValueError, TypeError):
            self.send_message({"error": f"Invalid parameters."})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            solve = bytes.fromhex(msg["solve"])

            if solve != self.secret_file:
                self.send_message({"error": "I don't like pudding."})
                self.close_connection()
                return

            self.numsolves += 1
            if self.numsolves == self.totalsolves:
                self.send_message({"flag": self.flag})
                self.close_connection()

            self.send_message(
                {"result": f"Clearly you just got lucky! Do it again {self.totalsolves - self.numsolves} times!"})
            self.db = defaultdict(bytes)
            self.place_flag()

        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    BackupServer.start_server("0.0.0.0", 50405, flag=flag)
