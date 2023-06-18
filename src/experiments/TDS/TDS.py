from pympler.asizeof import asizeof
import matplotlib.pyplot as plt

from random import randint
from typing import Callable
from timeit import timeit

from src.schemes.TDS.TimeDeniableSignatureScheme import TimeDeniableSignatureScheme
from src.experiments.config import N, P, M_test, MAX_test as T_test, V_test as t_test
from src.experiments.enums import *
from .TitleTDS import TitleTDS

SEC_TLP: int = 2048
""" TLP security parameter """

T_TLP: int = 5
""" TLP difficulty parameters """

SEC: int = [80, 112]
PAIRS: [str] = {
    80: 'SS512',
    112: 'SS1024',
}
""" Possible super singular curves """

BASE: [int] = [2, 5, 7, 10, 12, 14, 16, 19]
BASE_N: int = 16
""" Number system bases """

t, m, pair, T = t_test[0], M_test[0], PAIRS[SEC[0]], T_test[0]
""" Default test values """


TDS: TimeDeniableSignatureScheme = TimeDeniableSignatureScheme()
""" TDS scheme init """


def plot(x: [], y: [], title: TitleTDS, xlabel: Parameters, ylabel: Results):
    """ Plots the measurement results """
    plt.cla()
    plt.plot(x, y, 'ro')

    plt.title(title.value)

    plt.xlabel(xlabel.value)
    plt.ylabel(ylabel.value)

    plt.xticks(x, x)
    plt.yticks(y, y)

    plt.savefig(f"out/TDS/{title.value}.{xlabel.value}.png")


def measure_Sign_N():
    """ Measure signing time for different N """
    TIMESTAMP_COUNT: int = 50
    timestamps: [int] = [randint(0, 65_535) for _ in range(TIMESTAMP_COUNT)]
    T_avg: [] = []
    for b in BASE:
        _, SK = TDS.Gen(SEC_TLP, T_TLP, pair, b)

        T: float = 0.0
        for t in timestamps:
            T += timeit(lambda: TDS.Sign(SK, m, t), number=N) / N
        T_avg.append(round(T / TIMESTAMP_COUNT, P))
    plot(BASE, T_avg, TitleTDS.Sign, Parameters.N, Results.Time)


def measure_Gen(pair: str, T: int) -> float:
    """ Runs the key generation function N times and measures its speed """
    T_avg: float = timeit(lambda: TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N, T), number=N) / N

    return round(T_avg, P)


def measure_Gen_SEC():
    T_avg: [float] = [measure_Gen(PAIRS[sec], T) for sec in SEC]
    plot(SEC, T_avg, TitleTDS.Gen, Parameters.SEC, Results.Time)


def measure_Gen_T():
    T_avg: [float] = [measure_Gen(pair, T) for T in T_test]
    plot(T_test, T_avg, TitleTDS.Gen, Parameters.T, Results.Time)


def measure_Sign(pair: str, m: str, t: int) -> float:
    """ Runs the sign function N times and measures its speed """
    _, SK = TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N)

    T_avg: float = timeit(lambda: TDS.Sign(SK, m, t), number=N) / N

    return round(T_avg, P)


def measure_Sign_SEC():
    T_avg: [float] = [measure_Sign(PAIRS[sec], m, t) for sec in SEC]
    plot(SEC, T_avg, TitleTDS.Sign, Parameters.SEC, Results.Time)


def measure_Sign_m():
    T_avg: [float] = [measure_Sign(pair, m, t) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleTDS.Sign, Parameters.m, Results.Time)


def measure_Sign_t():
    T_avg: [float] = [measure_Sign(pair, m, t) for t in t_test]
    plot(t_test, T_avg, TitleTDS.Sign, Parameters.t, Results.Time)


def measure_Verify(pair: str, m: str, t: int) -> float:
    """ Runs the verify function N times and measures its speed """
    VK, SK = TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N)
    SIG = TDS.Sign(SK, m, t)

    T_avg: float = timeit(lambda: TDS.Verify(VK, SIG, m, t), number=N) / N

    return round(T_avg, P)


def measure_Verify_SEC():
    T_avg: [float] = [measure_Verify(PAIRS[sec], m, t) for sec in SEC]
    plot(SEC, T_avg, TitleTDS.Verify, Parameters.SEC, Results.Time)


def measure_Verify_m():
    T_avg: [float] = [measure_Verify(pair, m, t) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleTDS.Verify, Parameters.m, Results.Time)


def measure_Verify_t():
    T_avg: [float] = [measure_Verify(pair, m, t) for t in t_test]
    plot(t_test, T_avg, TitleTDS.Verify, Parameters.t, Results.Time)


def measure_AltSign(pair, m: str, t: int) -> float:
    """ Runs the altSign function N times and measures its speed """
    VK, SK = TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N)
    t_v: int = 256
    SIG = TDS.Sign(SK, m, t_v)

    T_avg: float = timeit(lambda: TDS.AltSign(VK, (m, t_v, SIG), m, t), number=N) / N

    return round(T_avg, P)


def measure_AltSign_SEC():
    T_avg: [float] = [measure_AltSign(PAIRS[sec], m, t) for sec in SEC]
    plot(SEC, T_avg, TitleTDS.AltSign, Parameters.SEC, Results.Time)


def measure_AltSign_m():
    T_avg: [float] = [measure_AltSign(pair, m, t) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleTDS.AltSign, Parameters.m, Results.Time)


def measure_AltSign_t():
    T_avg: [float] = [measure_AltSign(pair, m, t) for t in t_test]
    plot(t_test, T_avg, TitleTDS.AltSign, Parameters.t, Results.Time)


def measure_Sig(pair: str, m: str, t: int) -> int:
    """ Measure size of the signature """
    VK, SK = TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N)
    SIG = TDS.Sign(SK, m, t)

    return asizeof(SIG) // 1024


def measure_Sig_SEC():
    S: [int] = [measure_Sig(PAIRS[sec], m, t) for sec in SEC]
    plot(SEC, S, TitleTDS.Sig, Parameters.SEC, Results.Size)


def measure_Sig_m():
    S: [int] = [measure_Sig(pair, m, t) for m in M_test]
    plot([len(m) for m in M_test], S, TitleTDS.Sig, Parameters.m, Results.Size)


def measure_Sig_t():
    S: [int] = [measure_Sig(pair, m, t) for t in t_test]
    plot(t_test, S, TitleTDS.Sig, Parameters.t, Results.Size)


def measure_SchemeKey(pair: str, T: int) -> int:
    """ Measure size of the TDS scheme secret key """
    _, SK = TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N, T)

    return asizeof(SK) // 1024


def measure_SchemeKey_SEC():
    S: [int] = [measure_SchemeKey(PAIRS[sec], T) for sec in SEC]
    plot(SEC, S, TitleTDS.SchemeKey, Parameters.SEC, Results.Size)


def measure_SchemeKey_T():
    S: [int] = [measure_SchemeKey(pair, T) for T in T_test]
    plot(T_test, S, TitleTDS.SchemeKey, Parameters.T, Results.Size)


def measure_SigningKey(pair: str, t: int) -> int:
    """ Measure size of the signing key """
    _, SK = TDS.Gen(SEC_TLP, T_TLP, pair, BASE_N)
    SK_t: [] = TDS.FS.KeyGen(SK.K, t)

    return asizeof(SK_t) // 1024


def measure_SigningKey_SEC():
    S: [int] = [measure_SigningKey(PAIRS[sec], t) for sec in SEC]
    plot(SEC, S, TitleTDS.SigningKey, Parameters.SEC, Results.Size)


def measure_SigningKey_t():
    S: [int] = [measure_SigningKey(pair, t) for t in t_test]
    plot(t_test, S, TitleTDS.SigningKey, Parameters.t, Results.Size)


EXPERIMENTS: [Callable] = [
    measure_Sign_N,
    measure_SchemeKey_SEC,
    measure_SchemeKey_T,
    measure_SigningKey_SEC,
    measure_SigningKey_t,
    measure_Sig_SEC,
    measure_Sig_m,
    measure_Sig_t,
    measure_Gen_SEC,
    measure_Gen_T,
    measure_Sign_SEC,
    measure_Sign_m,
    measure_Sign_t,
    measure_Verify_SEC,
    measure_Verify_m,
    measure_Verify_t,
    measure_AltSign_SEC,
    measure_AltSign_m,
    measure_AltSign_t,
]
""" Experiments to run """
