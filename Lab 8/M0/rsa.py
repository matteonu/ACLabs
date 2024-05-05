from Crypto.Util import number
from Crypto.Random import random


def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)
    """
    e = 65537
    p = _get_special_prime(e,{e}, nbits//2)
    q = _get_special_prime(e, {e,p}, nbits//2)
    phi_N = (p-1)*(q-1)
    d = number.inverse(e, phi_N)
    #TODO: Take care of edge case where N becomes too large
    N = p*q
    return (N, e), (N, d), (p, q)

def _get_special_prime(coprime_to: int, excluded_numbers:set[int], nbits:int)->int:
    prime = number.getPrime(nbits)
    print(number.GCD(prime-1, coprime_to))
    while prime in excluded_numbers or not number.GCD(prime-1, coprime_to) == 1:
        prime = number.getPrime(nbits)
    return prime


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """
    return pow(m, pk[1], pk[0])



def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """
    return pow(c, sk[1], sk[0])
