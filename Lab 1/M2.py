from Crypto.Hash import SHA256

message = bytearray.fromhex(
    '210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002')
for i in range(255):
    try:
        print(str(i) + ": \n")
        print(bytes(a ^ i for a in message).decode(errors='replace'))
    except:
        print(bytes(a ^ i for a in message).hex())
