from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.DSA import DSA, DSAKey
import base64
import json

class DSAAlg(Algorithm):

    def __init__(self):
        implements = [Algorithm.KEY_GENERATION, Algorithm.SIGNATURE, Algorithm.VERIFICATION]
        super().__init__("DSA", implements)

    def generate_key(self, size: int = 2048) -> tuple[DSAKey, DSAKey]:
        return DSA.generate_key_pair(size)

    def Sign(self, msg: bytes, key: DSAKey):
        cipher: DSA = DSA(key)
        sig: bytes = cipher.sign(msg)
        og_msg_b64 = base64.b64encode(msg).decode("utf-8")

        jDict = {"original_message": og_msg_b64, "signature": sig}
        output = json.dumps(jDict, indent=2)
        return output

    def Verify(self, sig: str, key: DSAKey):
        try:
            jDict = json.loads(sig)
            og_msg = base64.b64decode(jDict["original_message"])
            signature = jDict["signature"]
            cipher: DSA = DSA(key)
            cipher.verify(signature, og_msg)
            return True
        except Exception:
            return False

    def export(self, key: DSAKey, location: str, password=b"", func=lambda msg, k: msg):
        key.export(file_name=location, pwd=password, enc_func=func)

    def load_key(self, location: str, password=b"", func=lambda msg, k: msg):
        return DSAKey.load(file_name=location, pwd=password, dec_func=func)
