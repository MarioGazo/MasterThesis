from enum import Enum


class TitleTDS(Enum):
    """ Labels for individual functions """
    Gen: str = 'TDS.Gen'
    Sign: str = 'TDS.Sign'
    Verify: str = 'TDS.Verify'
    AltSign: str = 'TDS.AltSign'
    Sig: str = 'TDS.Signature'
    SchemeKey: str = 'TDS.SchemeKey'
    SigningKey: str = 'TDS.SigningKey'
