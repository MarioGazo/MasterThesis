from random import randint, seed as seedRND, getrandbits  # Random int from start to end
from dataclasses import dataclass, astuple  # Data encapsulation
from libnum import generate_prime  # Generate primes
from sys import byteorder  # Little / Big endian

from Crypto.Cipher import Salsa20  # Symmetric encryption

SALSA20_NONCE_LENGTH: int = 8


@dataclass(frozen=True)
class TimeLockPuzzle:
    """ The time-lock puzzle holds a secret message tha can be obtained by solving it """
    N: int
    """ Composite modulus """
    A: int
    """ Squaring base """
    T: int
    """ Squaring amount """
    C_K: int
    """ Fuzzified key """
    C_M: bytes
    """ Encrypted secret message """

    def __iter__(self):
        return iter(astuple(self))


def Gen(SEC: int, M: bytes, T: int, S: int, seed: bytes = None) -> TimeLockPuzzle:
    """
    Time-lock puzzle generation algorithm encrypts the message so that it can be obtained by solving for the key and
    decrypting the encrypted message. Salsa20 symmetric encryption algorithm is used here.

    :param SEC: the security parameter
    :param M: the secret message to encrypt
    :param T: the amount of seconds to decrypt
    :param S: the amount of squaring operations per second
    :param seed: randomness seed value to create deterministic tlp

    :return: the generated time-lock puzzle
    """
    def pow_mod(A: int, E: int, N: int) -> int:
        """ Get (A^E) % N """
        R = 1  # Result buffer
        while E > 1:
            if E & 1:
                R = (R * A) % N
            A = A ** 2 % N
            E >>= 1
        return (A * R) % N

    # Get two random large prime numbers, deduce the composite modulus N and Φ(N)
    if seed:
        seedRND(seed + b'p')
    P: int = generate_prime(SEC // 2)
    if seed:
        seedRND(seed + b'q')
    Q: int = generate_prime(SEC // 2)

    N: int = P * Q
    phi_N: int = (P - 1) * (Q - 1)

    # Get the number of squaring operations
    O: int = T * S

    # Get a Salsa20 key, initialize the Salsa20 cipher and encrypt the secret message
    if seed:
        seedRND(seed + b'k')
    K: bytes = getrandbits(Salsa20.key_size[1] * 8).to_bytes(Salsa20.key_size[1], byteorder=byteorder)
    K_lock: bytes = int.to_bytes(
        int.from_bytes(K, byteorder=byteorder) % N, length=Salsa20.key_size[1], byteorder=byteorder
    )
    if seed:
        seedRND(seed + b'nonce')
    nonce = getrandbits(SALSA20_NONCE_LENGTH * 8).to_bytes(SALSA20_NONCE_LENGTH, byteorder=byteorder)
    salsa20Cipher: Salsa20.Salsa20Cipher = Salsa20.new(key=K_lock, nonce=nonce)
    C_M: bytes = salsa20Cipher.nonce + salsa20Cipher.encrypt(M)

    # Generate a random value, a ∈ (2, n)
    if seed:
        seedRND(seed + b'a')
    A: int = randint(2, N + 1)
    if seed:
        seedRND()

    # Exponent calculation
    E: int = (2**O) % phi_N

    # Calculate the exponentiation
    B: int = pow_mod(A, E, N)

    # Fuzzify the key by mixing it with the exponentiation
    C_K: int = (int.from_bytes(K, byteorder) % N + B) % N

    return TimeLockPuzzle(N, A, O, C_K, C_M)


def Sol(timeLockPuzzle: TimeLockPuzzle) -> bytes:
    """
    Time-lock puzzle solving algorithm performs the square operation a certain amount of time to obtain a key to decrypt
    the secret message.

    :param timeLockPuzzle: the time-lock puzzle to solve

    :return: the original secret message
    """
    N, A, T, C_K, C_M = timeLockPuzzle
    # Perform T square operations of A
    B: int = A % N
    for _ in range(T):
        B = B**2 % N

    # Defuzzify the key by mixing it with the exponentiation
    K: bytes = int.to_bytes((C_K - B) % N, length=Salsa20.key_size[1], byteorder=byteorder)

    # Decrypt the secret message and return it
    N, C = (C_M[:SALSA20_NONCE_LENGTH], C_M[SALSA20_NONCE_LENGTH:])

    return Salsa20.new(key=K, nonce=N).decrypt(C)
