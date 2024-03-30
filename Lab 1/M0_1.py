from Crypto.Hash import SHA256
print(SHA256.new(data=b'hi').hexdigest())
