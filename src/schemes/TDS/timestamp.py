from numpy import base_repr

settings: {} = {
    'base': 0,
    'digits': 0
}


def Init(B: int = 2, MAX: int = 65_535) -> None:
    """ Initializes the settings """
    settings['base'] = B
    settings['digits'] = len(base_repr(MAX, settings['base']))


def FormatTimestamp(T: int) -> str:
    """ Formats timestamp by switching the number into string, then pads with zeros """
    ret: str = base_repr(T, settings['base'])
    return '0' * (settings['digits'] - len(ret)) + ret
