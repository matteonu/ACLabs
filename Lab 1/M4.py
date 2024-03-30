from Crypto.Hash import SHA256


def xor(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))


c_1 = bytearray.fromhex(
    '9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0')
c_2 = bytearray.fromhex(
    'b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4')[:-6]

m = xor(c_1, c_2)
current = b'flag{'

result = b''

while (current):
    current = xor(current, m[0:5])
    print(current)
    m = m[5:]
    print(len(m))
    result = result + current
print(result)
