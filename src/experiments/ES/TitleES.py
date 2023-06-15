from enum import Enum


class TitleES(Enum):
    """ Labels for individual functions """
    Gen: str = 'ES.Gen'
    Sign: str = 'ES.Sign'
    Verify: str = 'ES.Verify'
    AltSign: str = 'ES.AltSign'
    Evolve: str = 'ES.Evolve'
    SchemeKey: str = 'ES.SchemeKey'
    SigningKey: str = 'ES.SigningKey'
    Sig: str = 'ES.Signature'
