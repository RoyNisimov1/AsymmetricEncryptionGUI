from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamal, ElGamalKey

class ElGamalAlg(Algorithm):

    def __init__(self):
        super().__init__("ElGamal")

    def Encrypt(self, msg: bytes, key: ElGamalKey, password=""):
        cipher: ElGamal = ElGamal(key)
        symmetric_key = AESWrapper.generate_key(password)
        encrypted_symmetric_key: bytes = cipher.encrypt(symmetric_key)
        encrypted_data = AESWrapper.encrypt(symmetric_key, msg)
        return encrypted_symmetric_key, encrypted_data

    def Decrypt(self, ct: tuple[bytes, bytes], key: ElGamalKey, password="") -> bytes:
        encrypted_symmetric_key, encrypted_data = ct
        cipher = ElGamal(key)
        symmetric_key = cipher.decrypt(encrypted_symmetric_key)
        msg = AESWrapper.decrypt(symmetric_key, encrypted_data)
        return msg

