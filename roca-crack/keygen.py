from functools import reduce
from math import log
from operator import mul
from os import remove
from subprocess import check_output

from Crypto.Util.number import getRandomNBitInteger, isPrime
from Crypto.PublicKey import RSA

# 0x10001 = 65537 (hardcoded public exponent, low hamming weight = fast)
e = 0x10001


def _prime_count_for_keysize(keysize):
    """Return the number of primes whose product forms the primorial M.

    Taken from section 2.1 "Format of the constructed primes" of the paper.
    """
    if 512 <= keysize <= 960:
        return 39
    elif 992 <= keysize <= 1952:
        return 71
    elif 1984 <= keysize <= 3936:
        return 126
    elif 3968 <= keysize <= 4096:
        return 225
    else:
        raise ValueError('Keysize is not in range for ROCA attack')


def _first_n_primes(n):
    """Generate the first :param:`n` prime numbers.

    Code is not optimally efficient but keygen only requires values of
    n < 1000 and for that it's fast enough and easy to read."""
    primes = [2]
    candidate = 3

    while len(primes) != n:
        # test if candidate is divisible by any prime smaller than it
        if not any([candidate % p == 0 for p in primes]):
            primes.append(candidate)

        candidate += 2  # only odds (beside 2) are prime, skip the evens

    return primes


def _check_msb(value, msb_index):
    """Ensure the top bit of the value is set."""
    msb = value >> (msb_index - 1)
    return msb == 1


def _get_prime(keysize):
    """Generate a candidate prime based on formula (1) in section 2.1."""
    candidate_prime = 0

    while not _check_msb(candidate_prime, keysize // 2):
        m = get_primorial(keysize)
        m_bits = int(log(m, 2))

        k_bits = (keysize // 2) - m_bits
        a_bits = {
            39: 62, 71: 134, 126: 255, 225: 434
        }[_prime_count_for_keysize(keysize)]  # Table 1 - Naive BF # attempts gives order of group
        k = getRandomNBitInteger(k_bits)
        a = getRandomNBitInteger(a_bits)

        candidate_prime = k * m + pow(e, a, m)

    return candidate_prime


def get_primorial(keysize):
    prime_count = _prime_count_for_keysize(keysize)
    primes = _first_n_primes(prime_count)
    return reduce(mul, primes)  # the primorial M in the paper


def generate_vulnerable_key(keysize=1024):
    """Generate an RSA object vulnerable to the ROCA attack"""
    p, q = 0, 0  # some non-prime values ...
    n = p * q

    while not _check_msb(n, keysize):
        while not isPrime(p):
            p = _get_prime(keysize)
        while not isPrime(q):
            q = _get_prime(keysize)
        n = p * q

    # generate only the public key (N, e), the whole point is to recover d
    rsa = RSA.construct((p*q, e))
    ascii_armored_key = rsa.exportKey().decode()
    print(ascii_armored_key)

    # run it against the roca-detect check utility
    tmpfile = 'tmp.pub'
    with open(tmpfile, 'w') as f:
        f.write(ascii_armored_key)
    print(check_output(['roca-detect', tmpfile]))
    remove(tmpfile)

    return rsa


if __name__ == '__main__':
    generate_vulnerable_key(keysize=512)
