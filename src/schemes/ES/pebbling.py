from dataclasses import dataclass, field, InitVar  # Data encapsulation
from typing import Any, Callable, Generator  # Type annotations
from hashlib import sha256, sha512  # Hashing
from functools import partial  # Partial function call
from copy import copy  # Object copying

from src.schemes.ES.XMSStree.DataStructure import XMSSPrivateKey, XMSSPublicKey
from src.schemes.ES.enums.Seed import Seed


@dataclass
class PebbleState:
    """ Represents a state machine which generates values based on the given initial value and the update function """

    pebbler: Generator = field(init=False)
    """ Get the next value from the reversed hash chain """
    val: InitVar
    """ Initial value """
    update: InitVar
    """ Update the current value function """
    E: InitVar
    """ Number of epochs """
    V: InitVar
    """ Number of epochs for which to precompute """

    def __post_init__(self, val: Any, update: Callable, E: int, V: int = 0):
        """ Initialize the pebbler and precompute V values """
        self.pebbler = _reverse_chain(E + V, copy(val), update)
        for _ in range(V):
            self.perform_update()

    def perform_update(self) -> Any:
        """ Updates the internal state if possible """
        return next(self.pebbler)


def update(SK: XMSSPrivateKey) -> XMSSPrivateKey:
    """ Get the next XMSS key """
    SK.idx += 1
    return copy(SK)


def random_value_factory(PK_static: XMSSPublicKey, SEC: int) -> Callable:
    """ Wraps the get_next_random function, so that not all the parameters have to be specified on each call """
    return partial(get_random_value, PK_static=PK_static, S=Seed.PEBBLE, SEC=SEC)


def get_random_value(r_prev: (bytes, int), PK_static: XMSSPublicKey, S: Seed, SEC: int) -> (bytes, int):
    """ Takes a previous random value and returns the next one in a deterministic way """
    return \
        hasher(r_prev[0] + bytes(PK_static.root_value) + str(r_prev[1] + 1).encode('ascii') + S.value, SEC), \
        r_prev[1] - 1


def hasher(m: bytes, SEC: int) -> bytes:
    """ Takes bytes m and returns a hash of a size given by the SEC parameter """
    try:
        return {
            256: sha256,
            512: sha512
        }[SEC](m).digest()
    except KeyError:
        raise Exception("SEC = {256, 512}")


def _reverse_chain(MAX: int, S: Any, update: Callable) -> Generator:
    """
    Optimal pebble P_k, optimized for speed
    Copyright (C) 2014 Berry Schoenmakers
    https://www.win.tue.nl/~berry/pebbling/

    Generates values which create a chain

    :param MAX: maximum number of values
    :param S: initial value
    :param update: get next value

    :return: next value
    """
    k = MAX.bit_length()
    z = []
    y = update(S)
    for h in range(1 << k, 1, -1):
        if bin(h).count('1') == 1:
            z.insert(0, y)
        y = update(y)

    for r in range((1 << k) - 1, 0, -1):
        if r == (1 << k) - MAX - 1:
            break
        yield z[0]
        c = r
        i = 0
        while ~c & 1:
            z[i] = z[i + 1]
            i += 1
            c >>= 1
        i += 1
        c >>= 1
        m = i
        s = 0
        while c:
            l = i
            while ~c & 1:
                i += 1
                c >>= 1
            j = r & ((1 << i) - 1)
            p = i & 1 ^ j & 1
            h = p + j * (i - m) + (m + 3 - l) * (1 << l) - (1 << m) >> 1
            q = h.bit_length() - 1
            for _ in range(p + i + 1 - s >> 1):
                y = copy(z[q])
                if h == 1 << q: q -= 1
                z[q] = update(y)
                h -= 1
            m = i
            s = m + 1
            while c & 1:
                i += 1
                c >>= 1
