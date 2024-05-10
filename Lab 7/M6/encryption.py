#!/usr/bin/env python

from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

...

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        """Initialize the AEAD cipher.

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
        self.enc_key = key[-enc_key_len:]

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

    def encrypt(self, pt: bytes, add_data: bytes = b'', iv: bytes = None):
        """Compute ciphertext and MAC tag.

        Keyword arguments:
        pt       -- plaintext
        add_data -- additional data
        iv       -- initialization vector
        """
        if iv is None:
            # Choose random IV.
            iv = get_random_bytes(self.block_len)

        al = self.computeAL(add_data)
        padded_ptxt = self._add_pt_padding(pt=pt)
        cbc = AES.new(key = self.enc_key, mode = AES.MODE_CBC, iv = iv)
        ct = cbc.encrypt(padded_ptxt)
        mac = HMAC.new(key = self.mac_key, digestmod=SHA256)
        mac.update(add_data)
        mac.update(iv + ct)
        mac.update(al)
        tag = mac.digest()[:-self.tag_len]


        return (iv + ct) + tag
    
    def decrypt(self, ctxt: bytes, add_data: bytes = b''):
        iv, ctxt, tag = ctxt[:self.block_len], ctxt[self.block_len:-self.tag_len], ctxt[-self.tag_len:]
        cbc = AES.new(key = self.enc_key, mode = AES.MODE_CBC, iv = iv)
        padded_ptxt = cbc.decrypt(ctxt)
        ptxt = self._remove_pt_padding(padded_ptxt)
        mac = HMAC.new(key = self.mac_key, digestmod=SHA256)
        al = self.computeAL(add_data)
        mac.update(add_data)
        mac.update(iv + ctxt)
        mac.update(al)
        if not mac.digest() == tag:
            raise ValueError("Bad MAC")
        return ptxt


    
    def computeAL(self, A: bytes):
        return (len(A) * 8).to_bytes(8)


def main():
    test_key = bytes.fromhex("""
        41206c6f6e6720726561642061626f75742073797374656d64206973207768617420796f75206e65656420616674657220746865206c6162
        """)
    test_c = bytes.fromhex("""
        bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab7df30af4ad0db52e
        """)
    ad = b''

    print(len(test_key))
    decryption =  CBC_HMAC(32, 24, test_key).decrypt(test_c)

if __name__ == "__main__":
    main()
