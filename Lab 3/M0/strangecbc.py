from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


class StrangeCBC():
    def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
        """Initialize the CBC cipher.
        """

        if iv is None:
            iv = get_random_bytes(block_length)

        self.iv = iv
        self.key = key
        self.block_length = block_length

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
        constant_bytes = int(1336).to_bytes(self.block_length, 'big')
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_plaintext = pad(plaintext, self.block_length)
        n_blocks = int(len(padded_plaintext)/self.block_length)
        ciphertext: bytes = bytes([])
        c_prev = self.iv
        for i in range(n_blocks):
            p_curr = padded_plaintext[
                i * self.block_length: (i+1) * self.block_length]
            c_curr = cipher.encrypt(xor(xor(p_curr, c_prev), constant_bytes))
            ciphertext = ciphertext.__add__(c_curr)
            c_prev = c_curr

        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        constant_bytes = int(1336).to_bytes(self.block_length, 'big')
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext: bytes = bytes([])
        c_prev = self.iv
        n_blocks = int(len(ciphertext)/self.block_length)
        for i in range(n_blocks):
            c_curr = ciphertext[
                i * self.block_length: (i+1) * self.block_length]
            p_curr = xor(
                xor(cipher.decrypt(ciphertext=c_curr), constant_bytes), c_prev)
            plaintext = plaintext.__add__(p_curr)
            c_prev = c_curr

        unpadded_plaintext = unpad(
            plaintext, self.block_length) if len(plaintext) > 0 else ''
        return unpadded_plaintext


def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
        "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
        "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
        "3fd46234ff7b62ad365d1db13bb249721b")
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")


if __name__ == "__main__":
    main()
