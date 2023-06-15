from src.TLP import *
from timeit import timeit


def get_squares_per_second():
    """ Get the amount of square operation that are adequate to a second of puzzle solving """
    T: int = 1
    """ One second """
    SEC: int = 2048
    """ Security parameter """
    M: bytes = b'hello'
    """ Message to encapsulate in the time-lock puzzle """
    S: int = 10_000
    """ Initial number of squares """

    while True:
        timeLockPuzzle: TimeLockPuzzle = GenTLP(SEC, M, T, S)
        result: float = timeit(lambda: SolTLP(timeLockPuzzle), number=1)

        print(f'{S} {result}')
        if result > 1.0:
            S -= round(S / 4)
        else:
            S += round(S / 4)

        if abs(result - 1.0) < 0.01:
            break


if __name__ == '__main__':
    get_squares_per_second()
