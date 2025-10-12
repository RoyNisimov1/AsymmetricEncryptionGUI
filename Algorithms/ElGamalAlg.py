from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamal, ElGamalKey
import base64
import json
class ElGamalAlg(Algorithm):

    def __init__(self):
        super().__init__("ElGamal")

    def Encrypt(self, msg: bytes, key: ElGamalKey, password=""):
        cipher: ElGamal = ElGamal(key)
        symmetric_key = AESWrapper.generate_key(password)
        encrypted_symmetric_key: bytes = cipher.encrypt(symmetric_key)
        encrypted_data = AESWrapper.encrypt(symmetric_key, msg)
        encrypted_symmetric_key_b64 = base64.b64encode(encrypted_symmetric_key).decode("utf-8")
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode("utf-8")
        jDict = {"encrypted_symmetric_key": encrypted_symmetric_key_b64, "encrypted_data": encrypted_data_b64}
        output = json.dumps(jDict, indent=2)
        return output

    def Decrypt(self, ct: str, key: ElGamalKey, password="") -> bytes:
        jDict = json.loads(ct)
        encrypted_symmetric_key = base64.b64decode(jDict["encrypted_symmetric_key"])
        encrypted_data = base64.b64decode(jDict["encrypted_data"])
        cipher = ElGamal(key)
        symmetric_key = cipher.decrypt(encrypted_symmetric_key)
        msg = AESWrapper.decrypt(symmetric_key, encrypted_data)
        return msg

