from pytest import mark
from os import urandom

from src.TLP.TimeLockPuzzle import *


DATA: [int] = [32, 64, 128, 512, 1024]
""" Security parameters """
T: int = 1
""" Time parameter """
S: int = 1
""" Difficulty parameter """
M_in: bytes = b'Hello'
""" Message """


@mark.parametrize("SEC", DATA)
def test_tlp_gen_and_sol(SEC):
    """ TLP generation and solving if the original message and the decrypted messages are the same """
    timeLockPuzzle: TimeLockPuzzle = Gen(SEC, M_in, T, S)
    M_out: bytes = Sol(timeLockPuzzle)

    assert M_in == M_out


@mark.parametrize("SEC", DATA)
def test_tlp_random(SEC):
    """ TLP will be generated on random """
    timeLockPuzzle1: TimeLockPuzzle = Gen(SEC, M_in, T, S)
    timeLockPuzzle2: TimeLockPuzzle = Gen(SEC, M_in, T, S)

    assert timeLockPuzzle1 != timeLockPuzzle2


@mark.parametrize("SEC", DATA)
def test_tlp_deterministic(SEC):
    """ TLP will be generated deterministically if generated with a seed """
    seed: bytes = urandom(32)

    timeLockPuzzle1: TimeLockPuzzle = Gen(SEC, M_in, T, S, seed)
    timeLockPuzzle2: TimeLockPuzzle = Gen(SEC, M_in, T, S, seed)

    assert timeLockPuzzle1 == timeLockPuzzle2
