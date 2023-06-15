from charm.toolbox.pairinggroup import GT

from src.schemes.TDS.schemes.HibeLWScheme import HibeLWScheme

pair = 'SS512'
""" Pairing curve for testing """


def test_encrypt_decrypt():
    """ HIBE can generate a key for an identity, this key can encrypt and decrypt """
    I = 'Hi!'

    hibe = HibeLWScheme()
    MSK, PP = hibe.Setup(pair)

    M_in = hibe.group.random(GT)
    CT = hibe.Encrypt(PP, M_in, I)

    _, SK_I = hibe.KeyGen(MSK, I)
    M_out = hibe.Decrypt(CT, SK_I)

    assert M_in == M_out


def test_delegation():
    """ Delegated key is valid and the superior identity key can decrypt its ciphertexts """
    I = "0"
    I2 = "00"
    I3 = "01"
    I4 = "0Hello"

    hibe = HibeLWScheme()
    (MSK, PP) = hibe.Setup(pair)

    _, SK = hibe.KeyGen(MSK, I)
    _, SK2 = hibe.Delegate(SK, I2)
    _, SK3 = hibe.Delegate(SK, I3)
    _, SK4 = hibe.Delegate(SK, I4)

    M_in = hibe.group.random(GT)
    for i, sk in [(I2, SK2), (I3, SK3), (I4, SK4)]:
        CT = hibe.Encrypt(PP, M_in, i)
        M_out = hibe.Decrypt(CT, sk)
        assert M_in == M_out

        M_out = hibe.Decrypt(CT, SK)
        assert M_in == M_out


def test_delegation_incorrect():
    """ Delegation can only happen if the prefix is the same """
    I = "0"
    I2 = "10"
    I3 = "11"

    hibe = HibeLWScheme()
    (MSK, PP) = hibe.Setup(pair)

    _, SK = hibe.KeyGen(MSK, I)
    _, SK2 = hibe.Delegate(SK, I2)
    _, SK3 = hibe.Delegate(SK, I3)

    M_in = hibe.group.random(GT)
    for i, sk in [(I2, SK2), (I3, SK3)]:
        CT = hibe.Encrypt(PP, M_in, i)
        M_out = hibe.Decrypt(CT, sk)
        assert M_in != M_out

        M_out = hibe.Decrypt(CT, SK)
        assert M_in != M_out
