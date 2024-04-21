#!/usr/bin/env python

from Crypto.Hash import SHA256


class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        """
        Initialize the AEAD cipher.

        Keyword arguments:
        enc_key_len  -- byte length of the encryption key
        mac_key_len  -- byte length of the mac key
        key          -- key bytes
        """

        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = mac_key_len

        # a correctly sized key must always be provided by the caller
        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")

        self.mac_key = key[:mac_key_len]
        self.enc_key = key[-mac_key_len:]

        self.block_len = 16

    def _add_pt_padding(self, pt: bytes):
        """Return padded plaintext"""
        padding_number = 16 - len(pt)%self.block_len
        padding = padding_number * padding_number.to_bytes()
        print(padding)

        return pt.__add__(padding)

    def _remove_pt_padding(self, pt: bytes):
        """Return unpadded plaintext"""
        if not len(pt)%self.block_len == 0:
            raise ValueError("Bad decryption")
        padding_length = int(pt[-1])
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Bad decryption")
        return pt[:-padding_length]
    
    def computeAL(self, A: bytes):
        return (len(A) * 8).to_bytes(8)


def main():
    res = ''
    aead = CBC_HMAC(16, 16, b''.join(bytes([i]) for i in range(32)))
    inputs = [b'a', b'a 23 bytes long string', b'64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes']
    paddings = ','.join([aead.computeAL(a).hex() for a in inputs])
    print(paddings)

if __name__ == "__main__":
    main()
