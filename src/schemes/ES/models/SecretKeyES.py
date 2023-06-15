from dataclasses import dataclass  # Data encapsulation

from Crypto.PublicKey.RSA import RsaKey

from src.schemes.ES.models.PublicKeyES import PublicKeyES
from src.schemes.ES.pebbling import PebbleState
from src.schemes.ES.models.Pinfo import Pinfo


@dataclass(frozen=True)
class SecretKeyES:
    """ Epochal signature scheme secret key representation """
    PK: PublicKeyES
    """ Public key of the ES scheme """
    S_r: (PebbleState, PebbleState)
    """ Tuple of random value pebbling both the new and the exp """
    S_sk: (PebbleState, PebbleState)
    """ Tuple of static key pebbling both the new and the exp """
    e: int
    """ Epoch number """
    SK_dynamic: RsaKey
    """ Secret dynamic key """
    pinfo_e: Pinfo
    """ Public information """

    @property
    def params(self) -> ():
        return self.PK, self.S_r, self.S_sk, self.e, self.SK_dynamic, self.pinfo_e
