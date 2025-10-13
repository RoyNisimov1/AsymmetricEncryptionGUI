import customtkinter as ctk

class TextBoxArea:

    def __init__(self, master, text="", font=("Ariel", 30)):

        self.master = master
        self.frame = ctk.CTkFrame(self.master, fg_color=("#D9D9D9", "#2B2B2B"))
        self.font = font


        self.text = text
        self.label = ctk.CTkLabel(self.frame, text=text, font=self.font)
        self.label.pack()

        self.box = ctk.CTkTextbox(self.frame, font=self.font)
        self.box.pack()

    def disable(self):
        self.box.configure(state="disabled")

    def enable(self):
        self.box.configure(state="normal")


    def get_value(self) -> str:
        return self.box.get("0.0", "end")

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        self.box.pack(**kwargs)

    def pack_forget(self):
        self.frame.pack_forget()







