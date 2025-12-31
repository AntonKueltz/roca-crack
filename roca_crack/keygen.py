from dataclasses import dataclass
from functools import reduce
from operator import mul
from random import getrandbits
from subprocess import check_output
from tempfile import NamedTemporaryFile

from roca_crack.algebra import first_n_primes

from Crypto.Util.number import isPrime
from Crypto.PublicKey.RSA import RsaKey, construct as construct_rsa


@dataclass
class RsaPrimeParams:
    primorial: int  # Section 2.1 - Format of the constructed primes
    a_bits: int  # Table 1 - Naive BF # attempts gives order of group


PARAMS_512_TO_960 = RsaPrimeParams(
    primorial=reduce(mul, first_n_primes(n=39)), a_bits=62
)
PARAMS_992_TO_1952 = RsaPrimeParams(
    primorial=reduce(mul, first_n_primes(n=71)), a_bits=134
)
PARAMS_1984_TO_3936 = RsaPrimeParams(
    primorial=reduce(mul, first_n_primes(n=126)), a_bits=255
)
PARAMS_3968_TO_4096 = RsaPrimeParams(
    primorial=reduce(mul, first_n_primes(n=225)), a_bits=434
)


def _get_prime_params(keysize: int) -> RsaPrimeParams:
    """Return the params needed to constuct a prime used as a factor in a vulnerable key."""
    if 512 <= keysize <= 960:
        return PARAMS_512_TO_960
    elif 992 <= keysize <= 1952:
        return PARAMS_992_TO_1952
    elif 1984 <= keysize <= 3936:
        return PARAMS_1984_TO_3936
    elif 3968 <= keysize <= 4096:
        return PARAMS_3968_TO_4096
    else:
        raise ValueError(f"Keysize {keysize} is not in range for ROCA attack")


def _get_prime(keysize: int) -> int:
    """Generate a candidate prime based on formula (1) in section 2.1."""
    candidate_prime = 0
    target_bit_length = keysize // 2

    params = _get_prime_params(keysize)
    # additional bit finds primes whose product is the desired keysize quicker
    k_bits = target_bit_length - params.primorial.bit_length() + 1

    while candidate_prime.bit_length() != target_bit_length or not isPrime(candidate_prime):
        k = getrandbits(k_bits)
        a = getrandbits(params.a_bits)

        # 0x10001 = 65537 (hardcoded public exponent, low hamming weight = fast)
        candidate_prime = k * params.primorial + pow(0x10001, a, params.primorial)

    return candidate_prime


def generate_vulnerable_key(keysize: int = 512) -> RsaKey:
    """Generate an RSA object vulnerable to the ROCA attack"""
    n = 0

    while n.bit_length() != keysize:
        p = _get_prime(keysize)
        q = _get_prime(keysize)
        n = p * q

    # generate only the public key (N, e), the whole point is to recover d
    rsa_key = construct_rsa((p * q, 0x10001))
    ascii_armored_key = rsa_key.exportKey().decode()

    print(ascii_armored_key)
    with NamedTemporaryFile(mode="w", delete=True) as f:
        f.write(ascii_armored_key)
        f.flush()
        print(check_output(["roca-detect", f.name]))

    return rsa_key
