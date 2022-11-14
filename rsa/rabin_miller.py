import random


__LOW_PRIMES__ = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
                  67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
                  157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                  251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349,
                  353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
                  457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
                  571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
                  673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                  797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
                  911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]


def rabin_miller(num: int, rounds_num: int = 10) -> bool:
    if num == 2 or num == 3:
        return True
    elif num < 2 or (num % 2) == 0:
        return False

    # presenting (num - 1) as 2^s * t
    t = num - 1
    s = 0
    while t % 2 == 0:
        t = t // 2
        s += 1

    # A cycle
    for trials in range(rounds_num):
        a = random.randrange(2, num - 1)
        x = pow(a, t, num)
        if x != 1:
            # B cycle
            i = 0
            while x != (num - 1):
                if i == s - 1:
                    return False
                else:
                    i = i + 1
                    x = pow(x, 2, num)
        return True

    return True


def is_prime(num: int) -> bool:
    if num < 2 or (num % 2) == 0:
        return False

    if num in __LOW_PRIMES__:
        return True

    for p in __LOW_PRIMES__:
        if (num % p) == 0:
            return False

    return rabin_miller(num)


def generate_large_prime(key_size: int = 1024) -> int:
    while True:
        num = random.randrange(pow(2, key_size - 1), pow(2, key_size))
        if is_prime(num):
            return num
