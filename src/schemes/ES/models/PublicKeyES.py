from dataclasses import dataclass  # Data encapsulation

from src.schemes.ES.XMSStree.DataStructure import XMSSPublicKey


@dataclass(frozen=True)
class PublicKeyES:
    """ Epochal signature scheme public key representation """

    PK_static: XMSSPublicKey
    """ Public static key """
    t0: int
    """ Unix timestamp with the start of the scheme time """
    D: int
    """ Duration of an epoch in seconds """
    E: int
    """ Number of valid epochs """
    V: int
    """ Number of epoch for which a signature is valid """
    SEC: int
    """ Security parameter """

    @property
    def params(self) -> ():
        return self.PK_static, self.t0, self.D, self.E, self.V, self.SEC
