from dataclasses import dataclass, field, InitVar  # Data encapsulation
from typing import Callable  # Type hint
from pickle import dumps  # Data to bytes

from Crypto.PublicKey.RSA import RsaKey

from src.schemes.ES.XMSStree.DataStructure import XMSSPrivateKey, SigXMSS
from src.schemes.ES.XMSStree.XMSS import XMSS_sign, ADRS
from src.TLP.TimeLockPuzzle import TimeLockPuzzle


@dataclass
class Pinfo:
    """ Public info for the current epoch representation """
    PK_dynamic: RsaKey
    """ Dynamic public key """
    e: int
    """ Epoch number """
    r: (bytes, int)
    """ Random value and it's pebbling value """
    SK_static_exp: XMSSPrivateKey
    """ Expired static secret key """
    tl: TimeLockPuzzle
    """ Time-lock puzzle with the new values """

    SIG_static: SigXMSS = field(init=False)
    """ Static signature """
    sk_new: InitVar
    """ Static secret key to sign the Pinfo with """
    w: InitVar
    """ XMSS w """
    h: InitVar
    """ XMSS h """
    hasher: InitVar
    """ XMSS hasher """

    def __post_init__(self, sk_new: XMSSPrivateKey, w: int, h: int, hasher: Callable) -> None:
        """ The object signs itself after you get all the values """
        self.SIG_static = XMSS_sign(hasher(self.static_args).digest(), sk_new, w, ADRS(), h, hasher)

    @property
    def params(self) -> ():
        """ Returns a tuple with important values """
        return self.PK_dynamic, self.e, self.r, self.SK_static_exp, self.tl, self.SIG_static

    @property
    def static_args(self) -> bytes:
        """ Turns all the arguments into bytes """
        return dumps((
            self.PK_dynamic.export_key(),
            self.e,
            self.r[0],
            self.SK_static_exp,
            self.tl
        ))

    def get_dynamic_args(self, m: str) -> bytes:
        """ Turns the pinfo_e and the message into bytes and returns their concatenation """
        return dumps((
            self.PK_dynamic.export_key(),
            self.e,
            self.r[0],
            self.SK_static_exp,
            self.tl,
            self.SIG_static,
            m.encode('ascii')
        ))
