import customtkinter as ctk


class RadiobuttonManager:

    def __init__(self, master, btns: list[str], font=("Ariel", 30)):

        self.master = master
        self.btns = btns
        self.frame = ctk.CTkFrame(self.master)

        self.chosen_alg_index = ctk.IntVar()
        alg_buttons = []
        for index, alg in enumerate(self.btns):
            radiobutton = ctk.CTkRadioButton(self.frame,
                                             text=alg,
                                             font=(font, 30),
                                             variable=self.chosen_alg_index,
                                             value=index,
                                             )
            alg_buttons.append(radiobutton)
            radiobutton.pack(side=ctk.LEFT, padx=10, pady=10)

    def pack(self):
        self.frame.pack()

    def pack_forget(self):
        self.frame.pack_forget()


