import tkinter as tk
import customtkinter as ctk

class entry_box:

    def __init__(self, master, text=""):

        self.master = master
        self.frame = ctk.CTkFrame(self.master)

        self.text = text
        self.label = ctk.CTkLabel(self.frame, text=text)
        self.label.pack()

        self.box = ctk.CTkEntry(self.frame)
        self.box.pack()

    def disable(self):
        self.box.configure(state="disabled")

    def enable(self):
        self.box.configure(state="normal")


    def get_value(self) -> str:
        return self.box.get()

    def pack(self, **kwargs):

        self.frame.pack(**kwargs)

    def pack_forget(self):
        self.frame.pack_forget()







