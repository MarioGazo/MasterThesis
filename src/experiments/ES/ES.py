import matplotlib.pyplot as plt

from typing import Callable
from timeit import timeit
from pympler.asizeof import asizeof

from src.schemes.ES.EpochalSignatureScheme import EpochalSignatureScheme as ES
from src.experiments.enums import Parameters, Results
from src.experiments.config import N, P, M_test, MAX_test as E_test, V_test as e_test
from .TitleES import TitleES

SEC_test: [int] = [256, 512]

sec, E, e, m = SEC_test[0], E_test[0], e_test[0], M_test[0]
""" Default parameters """


def plot(x: [], y: [], title: TitleES, xlabel: Parameters, ylabel: Results):
    """ Plots the measurement results """
    plt.cla()
    plt.plot(x, y, 'ro')

    plt.title(title.value)

    plt.xlabel(xlabel.value)
    plt.ylabel(ylabel.value)

    plt.xticks(x, x)
    plt.yticks(y, y)

    plt.savefig(f"out/ES/{title.value}.{xlabel.value}.png")


def measure_Gen(sec: int, E: int):
    """ Runs the key pair generation function N times and measures its speed """
    T: float = timeit(lambda: ES.Gen(sec, 1, E, 1), number=N) / N

    return round(T, P)


def measure_Gen_SEC():
    T_avg: [float] = [measure_Gen(sec, E) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.Gen, Parameters.SEC, Results.Time)


def measure_Gen_E():
    T_avg: [float] = [measure_Gen(sec, E) for E in E_test]
    plot(E_test, T_avg, TitleES.Gen, Parameters.E, Results.Time)


def measure_Sign(sec: int, m: str, e: int):
    """ Runs the signing function N times and measures its speed """
    _, SK = ES.Gen(sec, 1, E, 1)
    _, SK = ES.Evolve(SK)

    T: float = timeit(lambda: ES.Sign(SK, m), number=N) / N

    return round(T, P)


def measure_Sign_SEC():
    T_avg: [float] = [measure_Sign(sec, m, e) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.Sign, Parameters.SEC, Results.Time)


def measure_Sign_m():
    T_avg: [float] = [measure_Sign(sec, m, e) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleES.Sign, Parameters.m, Results.Time)


def measure_Sign_e():
    T_avg: [float] = [measure_Sign(sec, m, e) for e in e_test]
    plot(e_test, T_avg, TitleES.Sign, Parameters.e, Results.Time)


def measure_Verify(sec: int, m: str, e: int):
    """ Runs the signing function N times and measures its speed """
    PK, SK = ES.Gen(sec, 1, E, 1)
    _, SK = ES.Evolve(SK)
    SIG = ES.Sign(SK, m)
    T: float = timeit(lambda: ES.Verify(PK, 1, SIG, m, check_expired=False), number=N) / N

    return round(T, P)


def measure_Verify_SEC():
    T_avg: [float] = [measure_Verify(sec, m, e) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.Verify, Parameters.SEC, Results.Time)


def measure_Verify_m():
    T_avg: [float] = [measure_Verify(sec, m, e) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleES.Verify, Parameters.m, Results.Time)


def measure_Verify_e():
    T_avg: [float] = [measure_Verify(sec, m, e) for e in e_test]
    plot(e_test, T_avg, TitleES.Verify, Parameters.e, Results.Time)


def measure_AltSign(sec: int, m: str, e: int):
    """ Runs the forgery function N times and measures its speed """
    PK, SK = ES.Gen(sec, 1, E, 1)
    pinfo, SK = ES.Evolve(SK)
    T: float = timeit(lambda: ES.AltSign(PK, pinfo, e, m), number=N) / N

    return round(T, P)


def measure_AltSign_SEC():
    T_avg: [float] = [measure_AltSign(sec, m, e) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.AltSign, Parameters.SEC, Results.Time)


def measure_AltSign_m():
    T_avg: [float] = [measure_AltSign(sec, m, e) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleES.AltSign, Parameters.m, Results.Time)


def measure_AltSign_e():
    PK, SK = ES.Gen(sec, 1, E, 1)
    for i in range(E - 2):
        pinfo, SK = ES.Evolve(SK)

    T_avg: [float] = []
    for e in e_test:
        T: float = timeit(lambda: ES.AltSign(PK, pinfo, e, m), number=N) / N
        T_avg.append(round(T, P))

    plot(e_test, T_avg, TitleES.AltSign, Parameters.e, Results.Time)


def measure_Evolve(sec: int):
    """ Runs the evolve function N times and measures its speed """
    PK, SK = ES.Gen(sec, 1, N, 1)
    T: float = timeit(lambda: ES.Evolve(SK), number=N) / N

    return round(T, P)


def measure_Evolve_SEC():
    T_avg: [float] = [measure_Evolve(sec) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.Evolve, Parameters.SEC, Results.Time)


def measure_Sig(sec: int, e: int, m: str):
    """ Measures the size of the key """
    _, SK = ES.Gen(sec, 1, e, 1)
    _, SK = ES.Evolve(SK)
    SIG = ES.Sign(SK, m)

    return asizeof(SIG) // 1024


def measure_Sig_SEC():
    T_avg: [float] = [measure_Sig(sec, e, m) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.Sig, Parameters.SEC, Results.Size)


def measure_Sig_e():
    T_avg: [float] = [measure_Sig(sec, e, m) for e in e_test]
    plot(e_test, T_avg, TitleES.Sig, Parameters.e, Results.Size)


def measure_Sig_m():
    T_avg: [float] = [measure_Sig(sec, e, m) for m in M_test]
    plot([len(m) for m in M_test], T_avg, TitleES.Sig, Parameters.m, Results.Size)


def measure_SchemeKey(sec: int, E: int):
    """ Measures the size of the key """
    _, SK = ES.Gen(sec, 1, E, 1)
    _, SK = ES.Evolve(SK)

    return asizeof(SK) // 1024


def measure_SchemeKey_SEC():
    T_avg: [float] = [measure_SchemeKey(sec, E) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.SchemeKey, Parameters.SEC, Results.Size)


def measure_SchemeKey_E():
    T_avg: [float] = [measure_SchemeKey(sec, E) for E in E_test]
    plot(E_test, T_avg, TitleES.SchemeKey, Parameters.E, Results.Size)


def measure_SigningKey(sec: int, e: int):
    """ Measures size of the signing key for epoch e """
    _, SK = ES.Gen(sec, 1, E, 1)
    _, SK = ES.Evolve(SK)

    return asizeof(SK.SK_dynamic) // 1024


def measure_SigningKey_SEC():
    T_avg: [float] = [measure_SigningKey(sec, e) for sec in SEC_test]
    plot(SEC_test, T_avg, TitleES.SigningKey, Parameters.SEC, Results.Size)


def measure_SigningKey_e():
    T_avg: [float] = [measure_SigningKey(sec, e) for e in e_test]
    plot(e_test, T_avg, TitleES.SigningKey, Parameters.e, Results.Size)


EXPERIMENTS: [Callable] = [
    measure_SchemeKey_SEC,
    measure_SchemeKey_E,
    measure_SigningKey_SEC,
    measure_SigningKey_e,
    measure_Sig_SEC,
    measure_Sig_m,
    measure_Sig_e,
    measure_Gen_SEC,
    measure_Gen_E,
    measure_Sign_SEC,
    measure_Sign_m,
    measure_Sign_e,
    measure_Verify_SEC,
    measure_Verify_m,
    measure_Verify_e,
    measure_AltSign_SEC,
    measure_AltSign_m,
    measure_AltSign_e,
    measure_Evolve_SEC,
]
""" Experiments to run """
