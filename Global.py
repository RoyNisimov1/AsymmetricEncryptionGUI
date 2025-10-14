from Components.entry_box import EntryBox
from Algorithms.Algorithm import Algorithm
from Algorithms.RSAAlg import RSAAlg
from Algorithms.ElGamalAlg import ElGamalAlg
from Algorithms.DSAAlg import DSAAlg


class Global:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.init_instance()
        return cls._instance

    def init_instance(self):
        self.algorithms: list[Algorithm] = [RSAAlg(), ElGamalAlg(), DSAAlg()]
        self.root = None
        self.password_field = None
        self.selected_alg = self.algorithms[0]

    def set_alg(self, index):
        self.selected_alg = self.algorithms[index]

    def set_root(self, root):
        self.root = root

    def init_password_field(self):
        self.password_field = EntryBox(self.root, "Key password:")
        self.password_field.pack()
