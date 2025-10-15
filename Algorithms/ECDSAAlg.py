from .Algorithm import Algorithm
from AsymmetricEncryptions.PublicPrivateKey.ECC import ECKey, ECDSA,  EllipticCurveNISTP256, ECPoint
import base64
import json

class ECDSAAlg(Algorithm):

    CURVE = EllipticCurveNISTP256

    def __init__(self):
        implements = [Algorithm.KEY_GENERATION, Algorithm.SIGNATURE, Algorithm.VERIFICATION]
        super().__init__("ECDSA", implements)

    def generate_key(self, size: int = 2048) -> tuple[ECKey, ECKey]:
        key_pair = ECKey.new(ECDSAAlg.CURVE.get_curve())
        priv = key_pair
        pub = key_pair.get_public_key()
        return priv, pub

    def Sign(self, msg: bytes, key: ECKey):
        signer = ECDSA(key, key.get_public_key())
        sig: tuple[int, int] = signer.sign(msg)
        og_msg_b64 = base64.b64encode(msg).decode("utf-8")
        jDict = {"original_message": og_msg_b64, "signature": sig}
        output = json.dumps(jDict, indent=2)
        return output

    def Verify(self, sig: str, key: ECKey):
        try:
            jDict = json.loads(sig)
            og_msg = base64.b64decode(jDict["original_message"])
            signature = jDict["signature"]
            return ECDSA.verify(og_msg, key, signature)
        except Exception:
            return False


    def export(self, key: ECKey, location: str, password=b"", func=lambda msg, k: msg):
        key.export(file_name=location, pwd=password, enc_func=func)

    def load_key(self, location: str, password=b"", func=lambda msg, k: msg):
        return ECKey.load(file_name=location, pwd=password, dec_func=func)

    def get_has_private(self, key: ECKey):
        return key.private_key is not None