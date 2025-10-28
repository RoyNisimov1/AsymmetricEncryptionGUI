import customtkinter as ctk

from Global import Global


class RadiobuttonManager:

    def __init__(self, master, btns: list[str], command=lambda: None):

        self.master = master
        self.btns = btns
        self.frame = ctk.CTkFrame(self.master, fg_color=("#D9D9D9", "#2B2B2B"))
        self.command = command
        self.index = ctk.IntVar()
        alg_buttons = []
        for index, alg in enumerate(self.btns):
            radiobutton = ctk.CTkRadioButton(self.frame,
                                             text=alg, font=Global().font,
                                             variable=self.index,
                                             value=index, command=Global.button_click_sfx(self.command)
                                             )
            alg_buttons.append(radiobutton)
            radiobutton.pack(side=ctk.LEFT, padx=10, pady=10)

    def pack(self):
        self.frame.pack()

    def pack_forget(self):
        self.frame.pack_forget()


