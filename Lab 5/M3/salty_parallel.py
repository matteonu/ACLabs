from string import ascii_lowercase
import itertools
from hmac import HMAC
from multiprocessing import Pool, cpu_count

SALT = bytes.fromhex('b49d3002f2a089b371c3')
HASH = 'd262db83f67a37ff672cf5e1d0dfabc696e805bc'

def check_candidate(combination):
    candidate = ''.join(combination)
    if HASH == HMAC(candidate.encode(), SALT, digestmod='sha1').hexdigest():
        return candidate
    return None

if __name__ == '__main__':
    combinations = itertools.product(ascii_lowercase, repeat=6)
    num_processes = cpu_count()  # Number of CPU cores
    with Pool(num_processes) as pool:
        results = pool.map(check_candidate, combinations)
    
    # Print non-None results
    for result in results:
        if result is not None:
            print(result)