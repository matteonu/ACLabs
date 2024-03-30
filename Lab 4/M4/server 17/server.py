import secrets
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
        decryption = cipher.decrypt(ctxt)
        ptxt = cls.unpad(decryption)

        return ptxt


class BackupServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.users = dict()
        self.db = dict()

        self.numsolves = 0
        self.totalsolves = 40

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
        self.secret_file = secrets.token_bytes(100)
        file_id = secrets.token_bytes(15)
        self.db["admin"] = {
            file_id: self.secret_file
        }

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
            self.db[user] = dict()
            self.send_message({"result": "ok"})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("list")
    def handle_list(self, msg):
        """ List backed up files for a user.

        Given a user, return a list of all file IDs for that user's backups.
        """

        try:
            user = msg["user"]
            self.send_message({"result": list(file_id.hex()
                              for file_id in self.db[user].keys())})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("backup")
    def handle_backup(self, msg):
        """ Backup a new file for the user.

        Given a user and an encrypted backup file, decrypt the file and save it for the user.
        The file is assumed to be encrypted with the user"s key.
        """

        try:
            user = msg["user"]
            ctxt = msg["ctxt"]

            file = self.decrypt(user, ctxt)
            file_id = secrets.token_bytes(15)
            self.db[user][file_id] = file
            self.send_message({"result": file_id.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("get")
    def handle_get(self, msg):
        """ Get a backed up file.

        Given a user and an encrypted file ID, decrypt the file ID and return the corresponding file.
        The file ID is assumed to be encrypted with the user"s key.
        Since only the right user can encrypt the file ID with their key, this is secure.
        """

        try:
            user = msg["user"]
            ctxt = msg["ctxt"]

            file_id = self.decrypt(user, ctxt)

            if file_id not in self.db[user]:
                self.send_message({"error": "File not found!"})
                return

            file = self.db[user][file_id]
            self.send_message({"result": file.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})

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
            self.place_flag()

        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    BackupServer.start_server("0.0.0.0", 50404, flag=flag)
