def first_n_primes(n: int) -> list[int]:
    """Generate the first :param:`n` prime numbers.

    Code is not optimally efficient but keygen only requires values of
    n < 1000 and for that it's fast enough and easy to read."""
    primes = [2]
    candidate = 3

    while len(primes) != n:
        # test if candidate is divisible by any prime less than or equal to it's square root
        for p in primes:
            if p * p > candidate:
                primes.append(candidate)
                break
            elif candidate % p == 0:
                break

        candidate += 2  # only odds (beside 2) are prime, skip the evens

    return primes
