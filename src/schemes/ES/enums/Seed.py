from enum import Enum  # Constant value synonyms


class Seed(Enum):
    """ Values for random generators """
    PEBBLE = b'0'
    DYNAMIC_KEY = b'1'
    TIME_LOCK_PUZZLE = b'2'
