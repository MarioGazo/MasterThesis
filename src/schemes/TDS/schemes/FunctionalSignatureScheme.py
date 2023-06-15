from os.path import commonprefix  # Common prefix of a list of strings

from charm.toolbox.pairinggroup import GT, pc_element

from src.schemes.TDS.timestamp import FormatTimestamp
from .HibeLWScheme import HibeLWScheme


class FunctionalSignatureScheme:
    """ The FS scheme uses the underlying HIBE scheme to generate keys for timestamps and perform actions with them """

    HIBE: HibeLWScheme = None
    """ Underlying hierarchical identity based encryption scheme  """

    def __init__(self):
        self.HIBE = HibeLWScheme()

    def Setup(self, pair: str) -> ():
        """
        Generate the master verification key (MVK) and the master signing key (MSK)

        :param pair: ID of the pairing group

        :return: key pair (MVK, MSK)
        """
        MSK, PP = self.HIBE.Setup(pair)

        return PP, (MSK, PP)

    def KeyGen(self, MSK: (), T: int) -> ():
        """
        Generates a list of keys for a given timestamp T

        :param MSK: FS master signing key
        :param T: timestamp, represents a leaf node identity

        :return: a tuple of the public parameters and a list of keys
        """
        SK, PP = MSK
        trace: [[str]] = FunctionalSignatureScheme.Trace(T)
        SK_T: [[]] = [[self.HIBE.KeyGen(SK, N) for N in layer] for layer in trace]

        return PP, SK_T

    def Sign(self, SK_T: (), T: int, m: str, t: int) -> ():
        """
        Uses the underlying HIBE scheme to sign a message m for a timestamp t

        :param SK_T: list of keys from which it is possible to delegate any key where t <= T
        :param T: timestamp, represents max supported time
        :param m: message to sign
        :param t: timestamp for which to sign

        :return: tuple consisting a HIBE identity and a key for it
        """
        # Can only sign for timestamps up-until T
        if t > T:
            raise Exception("Can't create a signature for time after T")

        # Convert T and t to strings
        T_str: str = FormatTimestamp(T)
        t_str: str = FormatTimestamp(t)

        # Find a key that it's possible to delegate to the desired one from and do so
        prefix_length: int = len(commonprefix([t_str, T_str])) - int(t_str == T_str)

        _, l_sk = SK_T
        SK_layer: [] = l_sk[prefix_length]

        _, SKp = list(filter(lambda layer: layer[0] == t_str[:prefix_length + 1], SK_layer))[0]

        I, sk_tm = self.HIBE.Delegate(SKp, t_str + m)

        return I, sk_tm

    def Delegate(self, MVK: {}, T: int, SK_T: (), t: int) -> ():
        """
        Delegate a list of keys for time T to time t

        :param MVK: FS master verification key
        :param T: original timestamp
        :param SK_T: list of keys for the timestamp T
        :param t: timestamp to delegate to

        :return: tuple of the public key and the delegated list
        """
        # Can only delegate for timestamps up-until T
        if t > T:
            raise Exception("Can't create a signature for time after T")

        # Convert T and t to strings
        T_str: str = FormatTimestamp(T)
        t_str: str = FormatTimestamp(t)

        # Find common timestamp prefix and get the closes common signing key
        prefix_length: int = len(commonprefix([t_str, T_str])) - int(t_str == T_str)
        _, l_sk = SK_T
        SK_layer: [] = l_sk[prefix_length]
        _, SKp = list(filter(lambda layer: layer[0] == t_str[:prefix_length + 1], SK_layer))[0]

        # Compose delegated key list, re-randomize the common once and delegate the specific once
        SK_t: [[]] = []
        for layer in SK_T[1][:prefix_length]:
            SK_t.append([self.HIBE.Delegate(sk, i) for i, sk in layer])

        trace: [[str]] = FunctionalSignatureScheme.Trace(t)

        for layer in trace[prefix_length:]:
            SK_t.append([self.HIBE.Delegate(SKp, i) for i in layer])

        return MVK, SK_t

    def Verify(self, MVK: {}, TM: str, SIG) -> bool:
        """
        Uses the underlying HIBE scheme to verify the signature SIG

        :param MVK: FS master verification key
        :param TM: message and a timestamp concatenation
        :param SIG: signature

        :return: whether the signature is valid
        """
        _, I, S = SIG.params

        MSG: pc_element = self.HIBE.group.random(GT)
        C: dict = self.HIBE.Encrypt(MVK, MSG, TM)

        return self.HIBE.Decrypt(C, S) == MSG and TM == I

    @staticmethod
    def Trace(T: int) -> [[str]]:
        """
        Parse the given timestamp to a list of identity strings from the root

        :param T: timestamp, represents a leaf node identity

        :return: list of identities
        """
        T_str: str = FormatTimestamp(T)
        trace: [[str]] = []

        # Get the left siblings of the parent nodes
        digits: str = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        for i, c in enumerate(T_str, start=1):
            trace.append([T_str[:i - 1] + d for d in digits[:digits.find(c)]])

        # Add the T node itself
        trace[-1].append(T_str)

        return trace
