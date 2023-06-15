from src.schemes.ES.EpochalSignatureScheme import EpochalSignatureScheme

SEC: int = [256]
""" General security parameter """
M: str = 'hello'
""" Message to test with """
E: int = 10
""" Number of epochs """
V: int = 5
""" Number of epoch for which the signature is valid """


def test_signature_valid():
    """ Signature is valid for the epoch and the message """
    for s in SEC:
        ES: EpochalSignatureScheme = EpochalSignatureScheme()
        PK, SK = ES.Gen(s, 1, E, V)
        pinfo_e, SK = ES.Evolve(SK)

        SIG = ES.Sign(SK, M)

        for v in range(V):
            assert ES.Verify(SK.PK, 1 + v, SIG, M)
        assert not ES.Verify(SK.PK, 1 + V, SIG, M)


def test_signature_invalid():
    """ Signature is invalid for the epoch and the message """
    V: int = 1
    ES: EpochalSignatureScheme = EpochalSignatureScheme()

    for s in SEC:
        PK, SK = ES.Gen(s, 1, E, V)
        pinfo_e, SK = ES.Evolve(SK)
        pinfo_e, SK = ES.Evolve(SK)

        SIG = ES.Sign(SK, M)

        assert not ES.Verify(SK.PK, 1, SIG, 'olleh')
        assert not ES.Verify(SK.PK, 1, SIG, 'hello')
        assert not ES.Verify(SK.PK, 2, SIG, 'olleh')


def test_evolve_valid():
    """ Signature is valid during epoch changes """
    ES: EpochalSignatureScheme = EpochalSignatureScheme()
    for s in SEC:
        PK, SK = ES.Gen(s, 1, E, V)

        for i in range(1, E - V + 1):
            pinfo_e, SK = ES.Evolve(SK)
            SIG = ES.Sign(SK, M)

            for v in range(V):
                assert ES.Verify(SK.PK, i + v, SIG, M)
            assert not ES.Verify(SK.PK, i + V, SIG, M)


def test_expiration():
    """ Signatures validity expires after V epochs """
    ES: EpochalSignatureScheme = EpochalSignatureScheme()
    for s in SEC:
        PK, SK = ES.Gen(s, 1, E, V)

        for E_forge_for in range(1, E - V + 1):
            pinfo_e, SK = ES.Evolve(SK)

            SIG = ES.Sign(SK, M)

            for i in range(V):
                assert ES.Verify(SK.PK, E_forge_for + i, SIG, M)
            assert not ES.Verify(SK.PK, E_forge_for + V, SIG, M)


def test_forgery_pinfo():
    """ It is possible to forge a signature using the values from the pinfo_e """
    ES: EpochalSignatureScheme = EpochalSignatureScheme()
    for s in SEC:
        PK, SK = ES.Gen(s, 1, E, V)
        for _ in range(E):
            pinfo_e, SK = ES.Evolve(SK)

        for e in range(V + 1, E - V):
            altSIG = ES.AltSign(PK, pinfo_e, e, M)
            assert ES.Verify(PK, E, altSIG, M, check_expired=False)


def test_forgery_tlp():
    """ It is possible to forge a signature using the values from the time-lock puzzle """
    ES: EpochalSignatureScheme = EpochalSignatureScheme()
    for s in SEC:
        PK, SK = ES.Gen(s, 1, E, V)
        for e in range(1, E - V):
            pinfo_e, SK = ES.Evolve(SK)
            altSIG = ES.AltSign(PK, pinfo_e, e, M, use_tl=True)

            # Validity check
            for i in range(V):
                assert ES.Verify(PK, e + i, altSIG, M)
            assert not ES.Verify(PK, e + V, altSIG, M)
