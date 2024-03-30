from Crypto.Hash import SHA256


def otp(message, key):
    assert (len(message) == len(key))
    return bytes(m ^ k for (m, k) in zip(message, key)).hex()


print(otp(b'Pay no mind to the distant thunder, Beauty fills his head with wonder, boy', bytearray.fromhex(
    'bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f489f3454bbe1cab4510ccb979013277a7bf')))
