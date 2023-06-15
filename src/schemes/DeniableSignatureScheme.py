from abc import ABC, abstractmethod


class DeniableSignatureScheme(ABC):
    """ Each time-deniable signature scheme has to implement at least the following set of methods """
    @abstractmethod
    def Gen(self):
        """ Generate the secret key and the public key pair """
        pass

    @abstractmethod
    def Sign(self):
        """ Sign a given message for a timestamp with the secret key """
        pass

    @abstractmethod
    def AltSign(self):
        """ Sign a given message for a timestamp without the secret key """
        pass

    @abstractmethod
    def Verify(self):
        """ Verify a signature for a given message and a timestamp with the public key """
        pass
