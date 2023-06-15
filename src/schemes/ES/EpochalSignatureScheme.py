from hashlib import sha256, sha512  # Hashing
from pickle import dumps, loads  # Object from/to bytes
from time import time, sleep  # Timestamp and process idle
from os import urandom  # Random byte-stream

from Crypto.PublicKey.RSA import RsaKey

from src.schemes.DeniableSignatureScheme import DeniableSignatureScheme
from src.schemes.SignatureScheme import generate, sign, verify
from src.TLP import *
from . import *


TLP_S: int = 100_000
""" The amount of squaring operation per second (parameter for the time-lock puzzle) """

XMSS_VARIANTS: {} = {
    256: (32, 16, 67, 10, sha256),
    512: (64, 16, 131, 10, sha512)
}
""" Possible XMSS variants """

SEC_dynamic: int = 2048
""" Dynamic scheme security parameter length """


class EpochalSignatureScheme(DeniableSignatureScheme):
    """ Create ephemeral signatures which are valid during the duration of discrete time frames """

    @staticmethod
    def Gen(SEC: int, D: int, E: int, V: int) -> (PublicKeyES, SecretKeyES):
        """
        Generate the ES scheme key pair

        :param SEC: security parameter
        :param D: epoch duration in seconds
        :param E: the amount of epochs
        :param V: the amount of epochs for which a signature is valid (has to be larger than 0)

        :return: ES scheme key pair
        """
        # Generate the static key pair and the initial random value
        try:
            n, w, length, h, hasher = XMSS_VARIANTS[SEC]
        except KeyError:
            raise Exception("SEC = {256, 512}")
        SK_static, PK_static = XMSS_keyGen(n, w, h, hasher)

        # Initialise the pebbling states
        SK_new: PebbleState = PebbleState(SK_static, update, E, V)
        SK_exp: PebbleState = PebbleState(SK_static, update, E + V, 0)

        r_E = urandom(SEC // 8)
        next_random_value = random_value_factory(PK_static, SEC)
        SK_r_new: PebbleState = PebbleState((r_E, E), next_random_value, E, V)
        SK_r_exp: PebbleState = PebbleState((r_E, E), next_random_value, E + V, 0)

        # Compose the ES scheme key pair
        t0: float = time()
        PK: PublicKeyES = PublicKeyES(PK_static, t0, D, E, V, SEC)
        SK: SecretKeyES = SecretKeyES(PK, (SK_r_new, SK_r_exp), (SK_new, SK_exp), 0, None, None)

        return PK, SK

    @staticmethod
    def Evolve(SK: SecretKeyES) -> (Pinfo, SecretKeyES):
        """
        Derive the new epoch secret key from the previous epoch one

        :param SK: the current secret key

        :return: the public parameters for the new epoch and the new secret key
        """
        def sleep_until(T: float) -> None:
            """
            Taken from: https://github.com/jgillick/python-pause

            Sleep until the time given by the timestamp
            """
            while True:
                now = time()
                diff = T - now
                if diff <= 0:
                    break
                else:
                    sleep(diff / 2)

        # Get the previous epoch values and wait until the next epoch starts
        PK, (SK_r_new, SK_r_exp), (SK_new, SK_exp), e, _, _ = SK.params
        PK_static, t0, D, E, V, SEC = PK.params
        e_new: int = e + 1
        sleep_until(t0 + e_new * D)

        # Update the states
        r_new: (bytes, int) = SK_r_new.perform_update()
        r_exp: (bytes, int) = SK_r_exp.perform_update()
        sk_new: XMSSPrivateKey = SK_new.perform_update()
        sk_exp: XMSSPrivateKey = SK_exp.perform_update()

        # Get the next secret dynamic epoch key
        r_pk: (bytes, int) = EpochalSignatureScheme._get_r_pk_dynamic(r_new, PK_static, SEC)
        SK_dynamic, PK_dynamic = generate(SEC_dynamic, r_pk[0])

        # Create the time-lock puzzle with the current random value and the current secret key
        r_tl: (bytes, int) = EpochalSignatureScheme._get_r_tlp(r_new, PK_static, SEC)
        M_in: bytes = EpochalSignatureScheme._get_tlp_bytes(r_new, sk_new)
        tl: TimeLockPuzzle = GenTLP(SEC, M_in, V * D, TLP_S, r_tl[0])

        # Compose the public info and the new ES scheme secret key
        try:
            n, w, length, h, hasher = XMSS_VARIANTS[SEC]
        except KeyError:
            raise Exception("SEC = {256, 512}")
        pinfo_e_new: Pinfo = Pinfo(PK_dynamic, e_new, r_exp, sk_exp, tl, sk_new, w, h, hasher)
        SK: SecretKeyES = SecretKeyES(PK, (SK_r_new, SK_r_exp), (SK_new, SK_exp), e_new, SK_dynamic, pinfo_e_new)

        return pinfo_e_new, SK

    @staticmethod
    def Sign(SK: SecretKeyES, m: str) -> (int, Pinfo):
        """
        Use the current dynamic secret key to sign the message m

        :param SK: ES scheme secret key
        :param m: message to sign

        :return: signature and the current epoch info tuple
        """
        _, _, _, _, SK_dynamic, pinfo_e = SK.params

        SIG_dynamic: bytes = sign(SK_dynamic, pinfo_e.get_dynamic_args(m))

        return SIG_dynamic, pinfo_e

    @staticmethod
    def Verify(PK: PublicKeyES, e_current: int, SIG: (int, Pinfo), m: str, check_expired: bool = True) -> bool:
        """
        Validates the static and the dynamic signatures, if they are both valid, the signature is valid for the message

        :param PK: ES scheme public key
        :param e_current: current epoch number
        :param SIG: signature tuple
        :param m: message to validate signature for
        :param check_expired: check whether a signature is valid, even tho it is already expired (for testing purposes)

        :return: whether the signature is valid
        """
        # Get the values for the current epoch and the epoch when the signature was created
        PK_static, _, _, E, V, SEC = PK.params
        SIG_dynamic, pinfo_e = SIG
        PK_dynamic, e, _, _, _, SIG_static = pinfo_e.params

        # Make sure that the epoch is valid
        if e_current <= 0 or e <= 0 or e > e_current or e_current > E:
            return False
        if e + V <= e_current and check_expired:
            return False

        # Verify the static signature
        try:
            n, w, length, h, hasher = XMSS_VARIANTS[SEC]
        except KeyError:
            raise Exception("SEC = {256, 512}")
        valid_static: bool = XMSS_verify(
            SIG_static, hasher(pinfo_e.static_args).digest(), PK_static, w, PK_static.SEED, h, hasher
        )

        # Verify the dynamic signature
        valid_dynamic: bool = verify(PK_dynamic, pinfo_e.get_dynamic_args(m), SIG_dynamic)

        return valid_static and valid_dynamic

    @staticmethod
    def AltSign(PK: PublicKeyES, pinfo_e: Pinfo, eAlt: int, m: str, use_tl: bool = False) -> (int, Pinfo):
        """
        Creates a forgery of a dynamic signature for the message m on the epoch e

        :param PK: ES scheme current public key
        :param pinfo_e: public information
        :param eAlt: epoch to sign for
        :param m: message to sign
        :param use_tl: forge the signature by solving the time-lock puzzle

        :return: tuple of the forged signature and the public information
        """
        def solve_tlp(tlp: TimeLockPuzzle) -> (int, bytes, bytes):
            """ Solves the time-lock puzzle and returns the encoded key and the random value """
            M_in: bytes = SolTLP(tlp)
            M: {} = loads(M_in)

            return (M['r'], M['r_e']), M['sk']

        def extract_SK() -> ([RsaKey], [(bytes, int)]):
            """ Returns all the expired keys and random values starting from epoch e - 1 """
            SK_past: [XMSSPrivateKey] = [sk_e]
            R_past: [(bytes, int)] = [r_e]
            rounds: int = e - 1 if use_tl else e - 1 - PK.V
            for _ in range(rounds):
                sk_past = update(SK_past[0])
                SK_past.insert(0, sk_past)

                r_past = get_random_value(R_past[0], PK.PK_static, Seed.PEBBLE, SEC)
                R_past.insert(0, r_past)

            return SK_past, R_past

        # Get parameters either from the time-lock puzzle or the pinfo_e object
        SEC: int = PK.SEC
        e = pinfo_e.e
        if use_tl:
            r_e, sk_e = solve_tlp(pinfo_e.tl)
        else:
            r_e, sk_e = pinfo_e.r, pinfo_e.SK_static_exp

        # Get the expired keys and random values and choose the relevant once
        past: ([XMSSPrivateKey], [(bytes, int)]) = extract_SK()
        try:
            sk, r = past[0][eAlt - 1], past[1][eAlt - 1]
        except IndexError:
            raise Exception("Can't forge for future epochs")

        # Derive the needed dynamic signing key, the appropriate pinfo object and create a signature
        r_pk: (bytes, int) = EpochalSignatureScheme._get_r_pk_dynamic(r, PK.PK_static, SEC)
        SK_dynamic, PK_dynamic = generate(SEC_dynamic, r_pk[0])
        r_tl: (bytes, int) = EpochalSignatureScheme._get_r_tlp(r, PK.PK_static, SEC)
        M_in: bytes = EpochalSignatureScheme._get_tlp_bytes(r, sk)
        tl: TimeLockPuzzle = GenTLP(SEC, M_in, PK.V * PK.D, TLP_S, r_tl[0])

        sk_exp: XMSSPrivateKey = sk
        r_exp: (bytes, int) = r
        for _ in range(PK.V):
            sk_exp = update(sk_exp)
            r_exp = get_random_value(r_exp, PK.PK_static, Seed.PEBBLE, SEC)

        try:
            n, w, length, h, hasher = XMSS_VARIANTS[SEC]
        except KeyError:
            raise Exception("SEC = {256, 512}")
        pinfo_eAlt: Pinfo = Pinfo(PK_dynamic, eAlt, r_exp, sk_exp, tl, sk, w, h, hasher)
        SK_alt: SecretKeyES = SecretKeyES(None, None, None, None, SK_dynamic, pinfo_eAlt)

        return EpochalSignatureScheme.Sign(SK_alt, m)

    @staticmethod
    def _get_tlp_bytes(r: (bytes, int), sk: XMSSPrivateKey) -> bytes:
        """ Compose a message that will get en-locked in a time-lock puzzle """
        M: {} = {
            'r': r[0],
            'r_e': r[1],
            'sk': sk,
        }
        return dumps(M)

    @staticmethod
    def _get_r_pk_dynamic(r: (bytes, int), PK_static: XMSSPublicKey, SEC: int) -> (bytes, int):
        """ Calculate the random value needed to derive a dynamic public key """
        return get_random_value(r, PK_static, Seed.DYNAMIC_KEY, SEC)

    @staticmethod
    def _get_r_tlp(r: (bytes, int), PK_static: RsaKey, SEC: int) -> (bytes, int):
        """ Calculate the random value needed to derive the time-lock puzzle """
        return get_random_value(r, PK_static, Seed.TIME_LOCK_PUZZLE, SEC)
