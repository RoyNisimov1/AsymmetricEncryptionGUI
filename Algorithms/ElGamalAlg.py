from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.ElGamal import ElGamal, ElGamalKey
import base64
import json
class ElGamalAlg(Algorithm):

    def __init__(self):
        implements = [Algorithm.KEY_GENERATION, Algorithm.ENCRYPTION, Algorithm.DECRYPTION, Algorithm.SIGNATURE, Algorithm.VERIFICATION]

        super().__init__("ElGamal", implements)

    def generate_key(self, size: int = 2048) -> tuple[ElGamalKey, ElGamalKey]:
        return ElGamal.generate_key_pair(size)

    def Encrypt(self, msg: bytes, key: ElGamalKey, password=""):
        cipher: ElGamal = ElGamal(key)
        symmetric_key = AESWrapper.generate_key(password=password)
        encrypted_symmetric_key: tuple[bytes, bytes] = cipher.encrypt(symmetric_key)
        encrypted_data = AESWrapper.encrypt(symmetric_key, msg)
        encrypted_symmetric_key_c1_b64 = base64.b64encode(encrypted_symmetric_key[0]).decode("utf-8")
        encrypted_symmetric_key_c2_b64 = base64.b64encode(encrypted_symmetric_key[1]).decode("utf-8")
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode("utf-8")
        jDict = {"encrypted_symmetric_key_c1": encrypted_symmetric_key_c1_b64, "encrypted_symmetric_key_c2": encrypted_symmetric_key_c2_b64, "encrypted_data": encrypted_data_b64}
        output = json.dumps(jDict, indent=2)
        return output

    def Decrypt(self, ct: str, key: ElGamalKey, password="") -> bytes:
        try:
            jDict = json.loads(ct)
            encrypted_symmetric_key_c1 = base64.b64decode(jDict["encrypted_symmetric_key_c1"])
            encrypted_symmetric_key_c2 = base64.b64decode(jDict["encrypted_symmetric_key_c2"])
            encrypted_symmetric_key = (encrypted_symmetric_key_c1, encrypted_symmetric_key_c2)
            encrypted_data = base64.b64decode(jDict["encrypted_data"])
            cipher = ElGamal(key)
            symmetric_key = cipher.decrypt(encrypted_symmetric_key)
            msg = AESWrapper.decrypt(symmetric_key, encrypted_data)
            return msg
        except Exception:
            return ""

    def Sign(self, msg: bytes, key: ElGamalKey):
        cipher: ElGamal = ElGamal(key)
        sig: tuple[bytes, bytes, bytes] = cipher.sign(msg)
        og_msg_b64 = base64.b64encode(msg).decode("utf-8")
        signature_1_b64 = base64.b64encode(sig[0]).decode("utf-8")
        signature_2_b64 = base64.b64encode(sig[1]).decode("utf-8")
        signature_3_b64 = base64.b64encode(sig[2]).decode("utf-8")
        signature_list = [signature_1_b64, signature_2_b64, signature_3_b64]
        jDict = {"original_message": og_msg_b64, "signature": signature_list}
        output = json.dumps(jDict, indent=2)
        return output

    def Verify(self, sig: str, key: ElGamalKey):
        try:
            jDict = json.loads(sig)
            og_msg = base64.b64decode(jDict["original_message"])
            signature = jDict["signature"]
            signature_1 = base64.b64decode(signature[0])
            signature_2 = base64.b64decode(signature[1])
            signature_3 = base64.b64decode(signature[2])
            signature_final = (signature_1, signature_2, signature_3)
            cipher: ElGamal = ElGamal(key)
            cipher.verify(signature_final, og_message=og_msg)
            return True
        except Exception as e:
            return False

    def export(self, key: ElGamalKey, location: str, password=b"", func=lambda msg, k: msg):
        key.export(file_name=location, pwd=password, enc_func=func)

    def load_key(self, location: str, password=b"", func=lambda msg, k: msg):
        return ElGamalKey.load(file_name=location, pwd=password, dec_func=func)

