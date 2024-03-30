

from hashlib import md5
from hashlib import scrypt
from hmac import HMAC


""" def onion(pw, salt):
  h1 = md5(pw)
  h2 = HMAC[SHA1](h1, salt)
  h3 = HMAC[SHA256](h2, SECRET)
  # Use n = 2**10, r = 32, p = 2, key_len = 64
  h4 = scrypt(h3, salt)
  h5 = HMAC[SHA256](h4, salt)
  return h5 """

def onion(pw, salt, secret):
  m5 = md5()
  m5.update(pw)
  h1 = m5.digest()

  h2 = HMAC(salt, h1, digestmod='sha1').digest()

  h3 = HMAC(secret, h2, 'sha256').digest()

  h4 = scrypt(password=h3, salt=salt, n = 2**10, r = 32, p = 2, dklen = 64)

  h5 = HMAC(salt, h4, 'sha256').digest()
  return h5


PW = bytes.fromhex('6f6e696f6e732061726520736d656c6c79')
SECRET = bytes.fromhex('6275742061726520617765736f6d6520f09f988b')
SALT = bytes.fromhex('696e2061206e69636520736f6666726974746f21')
print(onion(PW, SALT, SECRET).hex())