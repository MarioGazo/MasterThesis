from typing import Callable
from os import urandom

from src.schemes.ES.EpochalSignatureScheme import XMSS_VARIANTS
from src.schemes.ES.pebbling import hasher, random_value_factory, PebbleState, update
from src.schemes.ES.XMSStree.DataStructure import XMSSPrivateKey
from src.schemes.ES.XMSStree.XMSS import XMSS_keyGen

SEC = [256]
""" General security parameter """
E = 4
""" Number of valid pebbling rounds """


def test_random_oracle_same():
    """ Generating a value from the same initial value """
    m: bytes = b'hello'

    for s in SEC:
        r1: bytes = hasher(m, s)
        r2: bytes = hasher(m, s)
        r3: bytes = hasher(m, s)

        assert len(r1) == len(r2) == len(r3) == s // 8
        assert len({r1, r2, r3}) == 1


def test_random_value_same():
    """ Generating the next random value with the same initial value gives the same value """
    for s in SEC:
        n, w, length, h, hasher = XMSS_VARIANTS[s]
        _, PK = XMSS_keyGen(n, w, h, hasher)
        init_r: bytes = urandom(s // 8)

        next_r: Callable = random_value_factory(PK, s)
        S1: PebbleState = PebbleState((init_r, E), next_r, E, 0)
        S2: PebbleState = PebbleState((init_r, E), next_r, E, 0)
        S3: PebbleState = PebbleState((init_r, E), next_r, E, 0)

        for _ in range(E):
            r1: bytes = S1.perform_update()
            r2: bytes = S2.perform_update()
            r3: bytes = S3.perform_update()

            assert len(r1[0]) == len(r2[0]) == len(r3[0]) == s // 8
            assert len({r1, r2, r3}) == 1


def test_random_value_diff():
    """ Generating the next random value with different initial value gives different value """
    for s in SEC:
        n, w, length, h, hasher = XMSS_VARIANTS[s]
        _, PK = XMSS_keyGen(n, w, h, hasher)
        R1, R2, R3 = urandom(s // 8), urandom(s // 8), urandom(s // 8)

        next_r: Callable = random_value_factory(PK, s)
        S1: PebbleState = PebbleState((R1, E), next_r, E, 0)
        S2: PebbleState = PebbleState((R2, E), next_r, E, 0)
        S3: PebbleState = PebbleState((R3, E), next_r, E, 0)

        for _ in range(E):
            r1: bytes = S1.perform_update()
            r2: bytes = S2.perform_update()
            r3: bytes = S3.perform_update()

            assert len(r1[0]) == len(r2[0]) == len(r3[0]) == s // 8
            assert len({r1, r2, r3}) == 3


def test_key_same():
    """ Generating the next key with the same initial key gives the same key """
    for s in [256]:
        n, w, length, h, hasher = XMSS_VARIANTS[s]
        SK, _ = XMSS_keyGen(n, w, h, hasher)

        S1: PebbleState = PebbleState(SK, update, E, 0)
        S2: PebbleState = PebbleState(SK, update, E, 0)
        S3: PebbleState = PebbleState(SK, update, E, 0)

        for _ in range(E):
            s1: XMSSPrivateKey = S1.perform_update()
            s2: XMSSPrivateKey = S2.perform_update()
            s3: XMSSPrivateKey = S3.perform_update()

            assert s1.idx == s2.idx == s3.idx


def test_key_diff():
    """ Generating the next key with different initial key gives different key """
    s = SEC[0]
    n, w, length, h, hasher = XMSS_VARIANTS[s]
    SK1, _ = XMSS_keyGen(n, w, h, hasher)
    SK2, _ = XMSS_keyGen(n, w, h, hasher)
    assert SK1.root_value != SK2.root_value

    S1: PebbleState = PebbleState(SK1, update, E, 0)
    S2: PebbleState = PebbleState(SK2, update, E, 0)

    for _ in range(E):
        s1: XMSSPrivateKey = S1.perform_update()
        s2: XMSSPrivateKey = S2.perform_update()

        assert s1 != s2


def test_pebble_values():
    """ Pebbling values create a hash chain """
    for s in SEC:
        n, w, length, h, hasher = XMSS_VARIANTS[s]
        _, PK = XMSS_keyGen(n, w, h, hasher)
        init_r: bytes = urandom(s // 8)

        next_r: Callable = random_value_factory(PK, s)
        S: PebbleState = PebbleState((init_r, E), next_r, E, 0)

        R_prev: [XMSSPrivateKey] = list(reversed([S.perform_update() for _ in range(E)]))
        for i in range(E - 1):
            assert R_prev[i + 1] == next_r(R_prev[i])


def test_key_retrieval():
    """ I am able to derive the keychain from the provided key """
    for s in SEC:
        n, w, length, h, hasher = XMSS_VARIANTS[s]
        SK, _ = XMSS_keyGen(n, w, h, hasher)

        S: PebbleState = PebbleState(SK, update, E, 0)
        SK_prev: [XMSSPrivateKey] = list(reversed([S.perform_update() for _ in range(E)]))

        for i in range(E - 1):
            assert SK_prev[i + 1].idx == update(SK_prev[i]).idx


def test_siblings():
    """ Two pebblers with the same seed, but with different offsets keep the offset throughout their run """
    for s in SEC:
        n, w, length, h, hasher = XMSS_VARIANTS[s]
        _, PK = XMSS_keyGen(n, w, h, hasher)
        V: int = 1

        init_r: bytes = urandom(s // 8)
        next_r: Callable = random_value_factory(PK, s)

        S1: PebbleState = PebbleState((init_r, E), next_r, E, 0)
        S2: PebbleState = PebbleState((init_r, E), next_r, E, V)

        S1_past: [bytes] = list(reversed([S1.perform_update() for _ in range(E)]))
        S2_past: [bytes] = list(reversed([S2.perform_update() for _ in range(E)]))

        for i in range(E - V):
            assert S1_past[i] == S2_past[i + V]
