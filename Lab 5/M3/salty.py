from string import ascii_lowercase
import itertools
from hmac import HMAC
from tqdm import tqdm

SALT = bytes.fromhex('b49d3002f2a089b371c3')
HASH = 'd262db83f67a37ff672cf5e1d0dfabc696e805bc'

combinations = itertools.product(ascii_lowercase, repeat=6)
combinations = tqdm(combinations ,total=26**6)
for combination in combinations:
    candidate = ''.join(combination)
    if HASH == HMAC(candidate.encode(), SALT, digestmod='sha1').hexdigest():
        print(candidate)
