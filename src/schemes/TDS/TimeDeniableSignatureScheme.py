from charm.core.engine.util import objectToBytes, bytesToObject  # Encode the list of keys to bytes

from src.schemes.DeniableSignatureScheme import DeniableSignatureScheme
from src.TLP import *

from .timestamp import FormatTimestamp, Init
from .schemes.FunctionalSignatureScheme import FunctionalSignatureScheme
from .models.SignatureTDS import SignatureTDS
from .models.KeyTDS import KeyTDS

S_TLP: int = 100_000
""" Number of squares per second """


class TimeDeniableSignatureScheme(DeniableSignatureScheme):
    """ The TDS scheme is used to create signatures that expire after the given time period """

    FS: FunctionalSignatureScheme = None
    """ Underlying functional signature scheme """

    def __init__(self):
        self.FS = FunctionalSignatureScheme()

    def Gen(self, SEC: int, T: int, pair: str, N: int = 2, MAX: int = 65_535) -> (KeyTDS, KeyTDS):
        """
        Generates the master signing key and the master verification key pair (VK, SK) from the underlying FS scheme

        :param SEC: security parameter
        :param T: TLP difficulty parameter
        :param pair: ID of the pairing group
        :param N: timestamp base (N = 2 -> binary, N = 10 -> deci, N = 16 -> hexa)
        :param MAX: the timestamp limit

        :return: key pair (PK, SK)
        """
        Init(N, MAX)  # Make sure all the timestamps share the same length
        MVK, MSK = self.FS.Setup(pair)

        return KeyTDS(MVK, T, SEC), KeyTDS(MSK, T, SEC)

    def Sign(self, SK: KeyTDS, m: str, t: int) -> SignatureTDS:
        """
        Creates a signature for a message m and a timestamp t

        :param SK: TDS master signing key
        :param m: message to sign
        :param t: timestamp for which to sign

        :return: time-deniable signature
        """
        MSK, T, SEC = SK.params

        # Get a list of keys for time t, sign the message
        SK_t: () = self.FS.KeyGen(MSK, t)
        I, S = self.FS.Sign(SK_t, t, m, t)

        # Encode the list of keys for t to bytes and initialize time-lock puzzle
        M: bytes = objectToBytes(SK_t, self.FS.HIBE.group)
        C: TimeLockPuzzle = GenTLP(SEC, M, T, S_TLP)

        return SignatureTDS(C, I, S)

    def AltSign(self, VK: KeyTDS, V: (), m: str, t: int) -> SignatureTDS:
        """
        Forge a signature of a message m and for timestamp t

        :param VK: TDS master verification key
        :param V: tuple of valid signature for a message and a timestamp (m*, t*, σ*)
        :param m: message to sign
        :param t: timestamp for which to sign

        :return: indistinguishable forged time-deniable signature
        """
        MVK, T, SEC = VK.params

        m_V, t_V, SIG_V = V
        C_V, V_V, S_V = SIG_V.params

        # Solve the time-lock puzzle and decode the bytes to a list of keys
        M: bytes = SolTLP(C_V)
        SK_t_V: [[]] = bytesToObject(M, self.FS.HIBE.group)

        # Get a list of keys for time t, sign the message
        SK_t: () = self.FS.Delegate(MVK, t_V, SK_t_V, t)
        I, S = self.FS.Sign(SK_t, t, m, t)

        # Encode the list of keys for t to bytes and initialize time-lock puzzle
        M: bytes = objectToBytes(SK_t, self.FS.HIBE.group)
        C: TimeLockPuzzle = GenTLP(SEC, M, T, S_TLP)

        return SignatureTDS(C, I, S)

    def Verify(self, VK: KeyTDS, SIG: SignatureTDS, m: str, t: int) -> bool:
        """
        Uses the underlying FS scheme to verify the signature SIG for a message m and a timestamp t

        :param VK: TDS master verification key
        :param SIG: signature to verify
        :param m: message to verify
        :param t: timestamp for which to verify
        :return: whether the signature is valid for the message and the timestamp
        """
        MVK, _, _ = VK.params
        t_str: str = FormatTimestamp(t)

        return self.FS.Verify(MVK, t_str + m, SIG)
