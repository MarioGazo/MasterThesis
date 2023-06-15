from pytest import mark

from src.schemes.TDS.timestamp import Init, FormatTimestamp

TIME: [int] = [1, 2, 4, 8, 32, 64, 128]
""" Timestamps """

BASE: [int] = [2, 3, 8, 10, 16]
""" Number system bases """


@mark.parametrize("T", TIME)
def test_length(T: int):
    """ Time should be formatted to string of the same length """
    Init(BASE[0])
    exp_length: int = len(FormatTimestamp(T))

    for t in TIME:
        if t > T:
            continue
        t_str: str = FormatTimestamp(t)
        assert len(t_str) == exp_length


@mark.parametrize("B", BASE)
def test_base(B: int):
    """ Time should be formatted correctly whatever the base """
    T: int = TIME[-1]

    Init(B)
    exp_length: int = len(FormatTimestamp(T))

    t_str: str = FormatTimestamp(T)
    assert len(t_str) == exp_length
