
class AlgorithmException(Exception):
    def __init__(self, message="Current algorithm doesn't support this."):
        self.message = message
        super().__init__(self.message)


class Algorithm:

    KEY_GENERATION = 0
    ENCRYPTION = 1
    DECRYPTION = 2
    SIGNATURE = 3
    VERIFICATION = 4


    def __init__(self, name: str, implements: list[str] = None):
        self.name: str = name
        if implements is None:
            implements = []
        self.implements = implements

    def generate_key(self, size: int):
        raise AlgorithmException("Current algorithm doesn't support Key Generation")

    def Encrypt(self, msg: bytes, key: object, password="") -> str:
        raise AlgorithmException("Current algorithm doesn't support encryption")

    def Decrypt(self, ct: str, key: object, password="") -> bytes:
        raise AlgorithmException("Current algorithm doesn't support decryption")

    def Sign(self, msg: bytes, key: object):
        raise AlgorithmException("Current algorithm doesn't support signing")

    def Verify(self, sig: bytes, key: object):
        raise AlgorithmException("Current algorithm doesn't support verification")

    def get_has_private(self, key: object) -> bool:
        raise AlgorithmException("Current algorithm doesn't support private keys")

    def load_key(self, location: str, password=b"", func=lambda msg, k: msg):
        raise AlgorithmException("Current algorithm doesn't support loading data")

    def export(self, key, location: str, password=b"", func=lambda msg, k: msg):
        raise AlgorithmException("Current algorithm doesn't support export data")
