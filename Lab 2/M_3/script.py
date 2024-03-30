from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from alive_progress import alive_bar

message = ...  # REDACTED
seed = ...  # REDACTED
iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")


def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key


def aes_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


# Be careful when running this script: it will override your existing flag.enc

ciphertext = bytes.fromhex(
    '79b04593c08cb44da3ed9393e3cbb094ad1ea5b7af8a40457ce87f2c3095e29980a28da9b2180061e56f61cd3ee023ebb08e8607bc44ae37682b1a4a39ca7eaf285b32f575a8bfb630ccd1548c6a7c6d78ceec8e1f45866a0f17bf5216c29ca3')
key_candidates = []
key_range = pow(256, 2)
with alive_bar(key_range) as bar:
    for i in range(key_range):
        key = generate_aes_key(i, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        bar()
        try:
            utf_8_string = plaintext.decode('utf-8')
            print("candidate found, the message could be: " + utf_8_string)
            key_candidates.append(key)

        except:
            continue

list_as_string = "\n".join(key_candidates)

# Write the string to a text file
with open("Lab 2/M_3/output.txt", "w") as file:
    file.write(list_as_string)
