from .Algorithm import Algorithm
from .AESWrapper import AESWrapper
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECKey, ECSchnorr, ECIES, EllipticCurveNISTP256, ECPoint
import base64
import json

class ECCAlg(Algorithm):

    CURVE = EllipticCurveNISTP256

    def __init__(self):
        implements = [Algorithm.KEY_GENERATION, Algorithm.ENCRYPTION, Algorithm.DECRYPTION, Algorithm.SIGNATURE, Algorithm.VERIFICATION]
        super().__init__("ECC", implements)

    def generate_key(self, size: int = 2048) -> tuple[ECKey, ECKey]:
        key_pair = ECKey.new(ECCAlg.CURVE.get_curve())
        priv = key_pair
        pub = key_pair.get_public_key()
        return priv, pub

    def Encrypt(self, msg: bytes, key: ECKey, password=""):
        encrypted_data = ECIES.encrypt(msg, key.public_key, encryption_function=lambda msg, key: AESWrapper.encrypt(AESWrapper.generate_key(password=password, salt=key), msg))
        encrypted_data_b64 = base64.b64encode(encrypted_data[0]).decode("utf-8")
        point = encrypted_data[1].export()
        jDict = {"encrypted_data": encrypted_data_b64, "point": point}
        output = json.dumps(jDict, indent=2)
        return output

    def Decrypt(self, ct: str, key: ECKey, password="") -> bytes:
        try:
            jDict = json.loads(ct)
            point = ECPoint.load(jDict["point"])
            encrypted_data = base64.b64decode(jDict["encrypted_data"])
            ciphertxt = (encrypted_data, point)
            msg = ECIES.decrypt(ciphertxt, key, decryption_function=lambda msg, key: AESWrapper.decrypt(AESWrapper.generate_key(password=password, salt=key), msg))
            return msg
        except Exception:
            return ""

    def Sign(self, msg: bytes, key: ECKey):
        signer = ECSchnorr(key)
        sig: tuple[int, ECPoint] = signer.sign(msg)
        og_msg_b64 = base64.b64encode(msg).decode("utf-8")
        signature_p = sig[1].export()
        jDict = {"original_message": og_msg_b64, "signature_a": sig[0], "signature_p": signature_p}
        output = json.dumps(jDict, indent=2)
        return output

    def Verify(self, sig: str, key: ECKey):
        try:
            jDict = json.loads(sig)
            og_msg = base64.b64decode(jDict["original_message"])
            signature_a = jDict["signature_a"]
            signature_p = ECPoint.load(jDict["signature_p"])
            signature = (signature_a, signature_p)
            return ECSchnorr.verify(signature, og_msg, key.public_key)
        except Exception:
            return False


    def export(self, key: ECKey, location: str, password=b"", func=lambda msg, k: msg):
        key.export(file_name=location, pwd=password, enc_func=func)

    def load_key(self, location: str, password=b"", func=lambda msg, k: msg):
        return ECKey.load(file_name=location, pwd=password, dec_func=func)

    def get_has_private(self, key: ECKey):
        return key.private_key is not None
