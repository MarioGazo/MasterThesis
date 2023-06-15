from src.schemes.TDS.TimeDeniableSignatureScheme import TimeDeniableSignatureScheme

SEC: int = 2048
""" Security parameter """

pair: str = 'SS512'
""" Pairing curve for testing """

T_TLP: int = 1
""" How many seconds should the TLP hold """

T: int = 5
""" Timestamp """

m: str = 'Hello!'
m_forge: str = '!olleH'
""" Messages """

BASE: [int] = [4, 10, 16]
""" Number system bases"""

TDS: TimeDeniableSignatureScheme = TimeDeniableSignatureScheme()
""" General TDS object """


def test_sign():
    """ TDS is able to create a signature for a message m and a time t and verify it """
    VK, SK = TDS.Gen(SEC, T_TLP, pair)
    for t in range(T + 1):
        SIG = TDS.Sign(SK, m, t)
        assert TDS.Verify(VK, SIG,  m, t)


def test_forge():
    """ TDS is able to forge a signature from another signature there t_forge <= t_valid """
    VK, SK = TDS.Gen(SEC, T_TLP, pair)

    SIG = TDS.Sign(SK, m, T)

    V = (m, T, SIG)
    for t_forge in range(T + 1):
        SIGAlt = TDS.AltSign(VK, V, m_forge, t_forge)
        assert TDS.Verify(VK, SIGAlt, m_forge, t_forge)


def test_sign_base():
    """ TDS is able to encode the timestamp using different base values """
    for b in BASE:
        VK, SK = TDS.Gen(SEC, T_TLP, pair, b)
        for t in range(T + 1):
            SIG = TDS.Sign(SK, m, t)
            assert TDS.Verify(VK, SIG, m, t)


def test_forge_base():
    """ TDS is able to forge a signature using different bases """
    for b in BASE:
        VK, SK = TDS.Gen(SEC, T_TLP, pair, b)

        SIG = TDS.Sign(SK, m, T)

        V = (m, T, SIG)
        for t_forge in range(T + 1):
            SIGAlt = TDS.AltSign(VK, V, m_forge, t_forge)
            assert TDS.Verify(VK, SIGAlt, m_forge, t_forge)
