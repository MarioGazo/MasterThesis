from dataclasses import dataclass

from charm.toolbox.pairinggroup import pc_element


@dataclass(frozen=True)
class KeyTDS:
    """ TDS scheme key definition """
    K: pc_element
    """ Key is a pairing group element """
    T: int
    """ Timestamp, represents the maximum supported time """
    SEC: int
    """ Security parameter """

    @property
    def params(self):
        return self.K, self.T, self.SEC
