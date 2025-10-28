from Components.entry_box import EntryBox
from Algorithms.Algorithm import Algorithm
from Algorithms.RSAAlg import RSAAlg
from Algorithms.ElGamalAlg import ElGamalAlg
from Algorithms.DSAAlg import DSAAlg
from Algorithms.ECCAlg import ECCAlg
from Algorithms.ECDSAAlg import ECDSAAlg

import pygame
import customtkinter

class Global:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.init_instance()
        return cls._instance

    def init_instance(self):
        self.button_click_sound = pygame.mixer.Sound("Assets/sfx/button_click.ogg")
        self.algorithms: list[Algorithm] = [RSAAlg(), ElGamalAlg(), DSAAlg(), ECCAlg(), ECDSAAlg()]
        self.font = customtkinter.CTkFont(family="Arial", size=20)
        self.root = None
        self.password_field = None
        self.selected_alg = self.algorithms[0]

    @staticmethod
    def button_click_sfx(func):
        def wrapper(*args, **kwargs):
            Global().button_click_sound.play()
            func(*args, **kwargs)
        return wrapper



    def set_alg(self, index):
        self.selected_alg = self.algorithms[index]

    def set_root(self, root):
        self.root = root

    def init_password_field(self):
        self.password_field = EntryBox(self.root, "Key password:", font=self.font)
        self.password_field.pack()

    @button_click_sfx
    def copy_to_clip_board(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

