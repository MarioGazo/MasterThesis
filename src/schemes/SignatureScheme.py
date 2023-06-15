from libnum import randint_bits  # Random bit stream
from random import seed  # Set randomness seed value
from sys import byteorder  # Little / Big Endian

from Crypto.PublicKey.RSA import RsaKey, generate as generateRSA
from Crypto.Hash.SHA512 import SHA512Hash, new as newSHA512
from Crypto.Signature import PKCS1_v1_5


def generate(SEC: int, r: bytes = b'') -> (RsaKey, RsaKey):
    """ Generates an RSA key pair from a seed or randomly """
    if r:
        seed(r)
        SK: RsaKey = generateRSA(SEC, randfunc=lambda x: randint_bits(x * 8).to_bytes(x, byteorder=byteorder))
        seed()
    else:
        SK: RsaKey = generateRSA(SEC)

    PK: RsaKey = SK.public_key()

    return SK, PK


def sign(SK: RsaKey, m: bytes) -> bytes:
    """ Create a signature for a message m using the RSA private key """
    hasher: SHA512Hash = newSHA512()
    hasher.update(m)
    signer: PKCS1_v1_5 = PKCS1_v1_5.new(SK)

    return signer.sign(hasher)


def verify(PK: RsaKey, m: bytes, SIG: bytes) -> bool:
    """ Verify a signature for a message m using the RSA public key """
    hasher: SHA512Hash = newSHA512()
    hasher.update(m)
    verifier: PKCS1_v1_5 = PKCS1_v1_5.new(PK)

    return verifier.verify(hasher, SIG)
