from typing import Tuple

from Crypto.PublicKey import ElGamal
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes

class ElGamalImpl:
    @classmethod
    def decrypt(cls, 
                key: ElGamal.ElGamalKey,
                c1: bytes,
                c2: bytes
                ) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """
        p = int(key.p) # modulus
        x = int(key.x) # private key

        K = pow(bytes_to_long(c1), x, p)
        K_inv = number.inverse(K, p)
        m = (bytes_to_long(c2) * K_inv) % p
        return long_to_bytes(m)

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """
        y = key.y # public key
        g = key.g # generator
        p = key.p # modulus
        k = number.getRandomRange(1, p-1)
        K = pow(y,k,p)
        c_1 = pow(g,k,p)
        c_2 = (K * bytes_to_long(msg)) % p
        return (long_to_bytes(c_1), long_to_bytes(c_2))
    
