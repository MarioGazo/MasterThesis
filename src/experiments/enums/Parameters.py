from enum import Enum


class Parameters(Enum):
    """ Labels for individual parameters """
    SEC: str = 'Security [b]'
    E: str = 'Max epoch [n]'
    e: str = 'Epoch [n]'
    m: str = 'Message [n]'
    t: str = 'Timestamp [s]'
    T: str = 'Max timestamp [s]'
    N: str = 'Base [n]'
