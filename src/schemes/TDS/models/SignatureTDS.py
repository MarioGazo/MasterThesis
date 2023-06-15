from dataclasses import dataclass

from charm.toolbox.pairinggroup import pc_element

from src.TLP.TimeLockPuzzle import TimeLockPuzzle


@dataclass(frozen=True)
class SignatureTDS:
    """ TDS scheme signature definition """
    C: TimeLockPuzzle
    """ Time-lock puzzle containing the list of keys from the root to the timestamp t """
    I: str
    """ HIBE identity of the signed message is a concatenation of the timestamp and the message """
    S: pc_element
    """ Signature is a HIBE key for the identity given by the timestamp and the message """

    @property
    def params(self):
        return self.C, self.I, self.S
