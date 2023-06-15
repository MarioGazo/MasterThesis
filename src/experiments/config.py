""" Constants used for experiment conduction """
from string import ascii_lowercase
from random import choice

N: int = 20
""" Number of runs to conduct per experiment """

P: int = 3
""" Number of measurement precision digits """

M_test: [str] = [
    ''.join(choice(ascii_lowercase) for _ in range(1)),
    ''.join(choice(ascii_lowercase) for _ in range(10)),
    ''.join(choice(ascii_lowercase) for _ in range(100)),
    ''.join(choice(ascii_lowercase) for _ in range(200))
]
""" Possible message values """

MAX_test: [int] = [254, 510, 1022]
""" Maximum time values """

V_test: [int] = [1, 10, 100, 200]
""" Time values """
