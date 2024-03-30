TARGET_LENGTH = 16
assert (TARGET_LENGTH % 8 == 0)

ptxt = str.encode('flag')
n_octets = TARGET_LENGTH
padding_length = n_octets - (len(ptxt) % n_octets)
print(padding_length)
print(len(ptxt))
for i in range(padding_length):
    ptxt += padding_length.to_bytes(1, 'big')
print(len(ptxt))
print(ptxt.hex())
