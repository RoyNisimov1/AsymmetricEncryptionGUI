from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSA, RSAKey

class RSAAlg(Algorithm):

    def __init__(self):
        implements = [Algorithm.KEY_GENERATION, Algorithm.ENCRYPTION, Algorithm.DECRYPTION, Algorithm.SIGNATURE, Algorithm.VERIFICATION]
        super().__init__("RSA", implements)

    def generate_key(self, size: int = 2048) -> tuple[RSAKey, RSAKey]:
        return RSA.generate_key_pair(size)

    def Encrypt(self, msg: bytes, key: RSAKey, password=""):
        cipher: RSA = RSA(key)
        symmetric_key = AESWrapper.generate_key(password)
        encrypted_symmetric_key: bytes = cipher.encrypt(symmetric_key)
        encrypted_data = AESWrapper.encrypt(symmetric_key, msg)
        return encrypted_symmetric_key, encrypted_data

    def Decrypt(self, ct: tuple[bytes, bytes], key: RSAKey, password="") -> bytes:
        encrypted_symmetric_key, encrypted_data = ct
        cipher = RSA(key)
        symmetric_key = cipher.decrypt(encrypted_symmetric_key)
        msg = AESWrapper.decrypt(symmetric_key, encrypted_data)
        return msg

