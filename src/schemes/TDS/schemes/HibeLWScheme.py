from numpy import prod  # Multipy list items

from charm.toolbox.pairinggroup import ZR, G1, pair, PairingGroup, pc_element  # Group operations
from charm.toolbox.matrixops import GaussEliminationinGroups  # Matrix operations


class HibeLWScheme:
    """
    Lewko-Waters HIBE scheme

    The original code of this class is taken over from the charm library charm.schemes.hibenc.hibenc_lew11 authored
    by N. Fotiou. It is refactored for better readability.
    """

    group: PairingGroup
    """ Group for random number generation """

    def Setup(self, pairID: int) -> (dict, dict):
        """
        Set up the HIBE scheme

        :param pairID: ID of the pairing group

        :return: master signing key and the public parameters
        """
        # Choose bi-linear group
        self.group = PairingGroup(pairID)

        # Sample random dual orthonormal basis
        B: pc_element = self.group.random()
        D: [] = [[self.group.random() for _ in range(10)] for _ in range(10)]
        D_star: [] = []
        for i, d_i in enumerate(D):
            gauss = [d + [self.group.init(ZR, 0)] for d in D]
            gauss[i] = d_i + [B]
            D_star.append(GaussEliminationinGroups(gauss))

        # Compose the public parameters PP
        g: pc_element = self.group.random(G1)
        A1, A2 = self.group.random(count=2)
        PP: {} = {
            'e1': pair(g, g) ** (A1 * B),
            'e2': pair(g, g) ** (A2 * B),
            'g': [[g ** d for d in d_i] for i, d_i in enumerate(D[0:6])]
        }

        # Compose the master secret key MSK
        theta, sigma, gamma, ksi = self.group.random(count=4)
        G: [] = [
            [g ** d for d in D_star[0]],  # 0
            [g ** d for d in D_star[1]],  # 1
            [g ** (d * gamma) for d in D_star[0]],  # 2
            [g ** (d * ksi) for d in D_star[1]],    # 3
            [g ** (d * theta) for d in D_star[2]],  # 4
            [g ** (d * theta) for d in D_star[3]],  # 5
            [g ** (d * sigma) for d in D_star[4]],  # 6
            [g ** (d * sigma) for d in D_star[5]],  # 7
        ]
        MSK: {} = {
            'a1': A1,
            'a2': A2,
            'g': G
        }

        return MSK, PP

    def KeyGen(self, MSK: dict, I: str) -> ():
        """
        Generate a key for a given identity

        :param MSK: HIBE master secret key
        :param I: identity

        :return: identity and a key
        """
        # Random values
        R1: [pc_element] = [self.group.random() for _ in I]
        R2: [pc_element] = [self.group.random() for _ in I]

        # Random values where sum(Y) = MSK.a1 and sum(W) = MSK.a2
        Y: [pc_element] = [self.group.random() for _ in range(len(I) - 1)]
        Y.append(MSK['a1'] - sum(Y))
        W: [pc_element] = [self.group.random() for _ in range(len(I) - 1)]
        W.append(MSK['a2'] - sum(W))

        # Compute the identity key
        K: [] = []
        for i, y, w, r1, r2 in zip(I, Y, W, R1, R2):
            g: [] = [
                [msk_g_0 ** y for msk_g_0 in MSK['g'][0]],  # 0
                [msk_g_1 ** w for msk_g_1 in MSK['g'][1]],  # 1
                [msk_g_4 ** (r1 * self.group.hash(i)) for msk_g_4 in MSK['g'][4]],  # 4
                [msk_g_5 ** (-r1) for msk_g_5 in MSK['g'][5]],  # 5
                [msk_g_6 ** (r2 * self.group.hash(i)) for msk_g_6 in MSK['g'][6]],  # 6
                [msk_g_7 ** (-r2) for msk_g_7 in MSK['g'][7]]  # 7
            ]
            K.append([prod([g[x] for g in g]) for x in range(10)])
        g: [] = MSK['g'][2:8]

        return I, {'g': g, 'K': K}  # Secret Key SK

    def Delegate(self, SK: dict, I: list) -> dict:
        """
        Derives a delegated key from a superior one

        :param SK: superior key
        :param I: identity to delegate to

        :return: delegated key
        """
        # Random values
        W1: [pc_element] = [self.group.random() for _ in I]
        W2: [pc_element] = [self.group.random() for _ in I]

        # Random values where sum(Y) = MSK.a1 and sum(W) = MSK.a2
        Y: [pc_element] = [self.group.random() for _ in range(len(I) - 1)]
        Y.append(0 - sum(Y))
        W: [pc_element] = [self.group.random() for _ in range(len(I) - 1)]
        W.append(0 - sum(W))

        # Compute the delegated identity key
        K: [] = []
        for idx, (i, y, w, w1, w2) in enumerate(zip(I, Y, W, W1, W2)):
            G: [] = [
                [sk_g_0 ** y for sk_g_0 in SK['g'][0]],  # 0
                [sk_g_1 ** w for sk_g_1 in SK['g'][1]],  # 1
                [sk_g_2 ** (w1 * self.group.hash(i)) for sk_g_2 in SK['g'][2]],  # 2
                [sk_g_3 ** -w1 for sk_g_3 in SK['g'][3]],  # 3
                [sk_g_4 ** (w2 * self.group.hash(i)) for sk_g_4 in SK['g'][4]],  # 4
                [sk_g_5 ** (-w2) for sk_g_5 in SK['g'][5]],  # 5
            ]
            if idx < len(SK['K']):
                K.append([prod([SK['K'][idx][x]] + [g[x] for g in G]) for x in range(10)])
            else:
                K.append([prod([g[x] for g in G]) for x in range(10)])

        return I, {'g': SK['g'], 'K': K}  # Secret Key SK

    def Encrypt(self, PP: dict, M: pc_element, I: str) -> dict:
        """
        Encrypts the message

        :param PP: HIBE scheme public parameters
        :param M: message to encrypt
        :param I: identity

        :return: cipher text
        """
        # Random values
        S1, S2 = self.group.random(count=2)
        T1: [pc_element] = [self.group.random() for _ in I]
        T2: [pc_element] = [self.group.random() for _ in I]

        # Compute the cipher text
        G: [] = [0] * 6
        G[0] = [pp_g_0 ** S1 for pp_g_0 in PP['g'][0]]
        G[1] = [pp_g_1 ** S2 for pp_g_1 in PP['g'][1]]

        C: [] = []
        for i, t1, t2 in zip(I, T1, T2):
            G[2] = [pp_g_2 ** t1 for pp_g_2 in PP['g'][2]]
            G[3] = [pp_g_3 ** (t1 * self.group.hash(i)) for pp_g_3 in PP['g'][3]]
            G[4] = [pp_g_4 ** t2 for pp_g_4 in PP['g'][4]]
            G[5] = [pp_g_5 ** (t2 * self.group.hash(i)) for pp_g_5 in PP['g'][5]]
            C.append([prod([g[x] for g in G]) for x in range(10)])

        C0: pc_element = M * (PP['e1'] ** S1) * (PP['e2'] ** S2)

        return {'C0': C0, 'C': C}  # Cipher Text CT

    @staticmethod
    def Decrypt(CT: dict, SK: dict) -> pc_element:
        """
        Decrypt the cipher text to get the original message

        :param CT: cipher text
        :param SK: secret key

        :return: decrypted secret message
        """
        # Compute the message
        B: int = 1
        for ct_c, sk_k in zip(CT['C'], SK['K']):
            B *= prod([pair(c, k) for c, k in zip(ct_c, sk_k)])

        return CT['C0'] / B  # Message M
