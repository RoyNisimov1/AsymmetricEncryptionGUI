from Algorithms.Algorithm import Algorithm
from Algorithms.RSAAlg import RSAAlg
from Algorithms.ElGamalAlg import ElGamalAlg


class Global:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.__init__()
        return cls._instance

    def __init__(self):
       self.algorithms: list[Algorithm] = [RSAAlg(), ElGamalAlg()]