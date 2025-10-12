from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.RSA import RSA, RSAKey
import base64
import json

class RSAAlg(Algorithm):

    def __init__(self):
        implements = [Algorithm.KEY_GENERATION, Algorithm.ENCRYPTION, Algorithm.DECRYPTION, Algorithm.SIGNATURE, Algorithm.VERIFICATION]
        super().__init__("RSA", implements)

    def generate_key(self, size: int = 2048) -> tuple[RSAKey, RSAKey]:
        return RSA.generate_key_pair(size)

    def Encrypt(self, msg: bytes, key: RSAKey, password=""):
        cipher: RSA = RSA(key)
        symmetric_key = AESWrapper.generate_key(password=password)
        encrypted_symmetric_key: bytes = cipher.encrypt(symmetric_key)
        encrypted_data = AESWrapper.encrypt(symmetric_key, msg)
        encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode("utf-8")
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode("utf-8")
        jDict = {"encrypted_symmetric_key": encrypted_symmetric_key_b64, "encrypted_data": encrypted_data_b64}
        output = json.dumps(jDict, indent=2)
        return output

    def Decrypt(self, ct: str, key: RSAKey, password="") -> bytes:
        jDict = json.loads(ct)
        encrypted_symmetric_key = base64.b64decode(jDict["encrypted_symmetric_key"])
        encrypted_data = base64.b64decode(jDict["encrypted_data"])
        cipher = RSA(key)
        symmetric_key = cipher.decrypt(encrypted_symmetric_key)
        msg = AESWrapper.decrypt(symmetric_key, encrypted_data)
        return msg


    def export(self, key: RSAKey, location: str, password=b"", func=lambda msg, k: msg):
        key.export(file_name=location, pwd=password, enc_func=func)

    def load_key(self, location: str, password=b"", func=lambda msg, k: msg):
        return RSAKey.load(file_name=location, pwd=password, dec_func=func)


