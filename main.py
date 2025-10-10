import tkinter as tk
from tkinter import filedialog
from Global import Global
from Algorithms.Algorithm import Algorithm

if __name__ == "__main__":
    FONT = "Ariel"
    BG_COLOR = "#5668A9"
    BG_COLOR_2 = "#5692A9"
    FG_COLOR = "#A99756"

    # -------------- Initialise window --------------- #
    root = tk.Tk()
    root.title("Clavis")
    icon = tk.PhotoImage(file="Assets/Clavis.png")
    root.iconphoto(True, icon)
    root.config(bg=BG_COLOR)
    try:
        root.state("zoomed")
    except tk.TclError:
        root.attributes("-zoomed", True)
    root.update_idletasks()
    # -------------- Algorithm choosing widgets -------------- #
    alg_frame = tk.Frame(root, bg=BG_COLOR)
    alg_frame.pack(pady=10, anchor="w")
    chosen_alg_index = tk.IntVar()
    alg_buttons = []
    for index, alg in enumerate(Global().algorithms):
        radiobutton = tk.Radiobutton(alg_frame,
                                     text=alg.name,
                                     font=(FONT, 30),
                                     variable=chosen_alg_index,
                                     value=index,
                                     padx=10,
                                     bg=BG_COLOR,
                                     activebackground=FG_COLOR,
                                     )
        alg_buttons.append(radiobutton)
        radiobutton.pack(side=tk.LEFT)
    selected_alg = Global().algorithms[chosen_alg_index.get()]

    # ------------- Select keyfile ------------------ #
    selected_file = tk.StringVar()

    buttons = []
    def show_buttons():
        for button in buttons:
            button.pack(side=tk.LEFT)

    def hide_buttons():
        for button in buttons:
            button.pack_forget()
        func_var.set(0)

    def select_file():
        global selected_file
        file_path = tk.filedialog.askopenfilename(
            title="Select a File",
            initialdir="/",
            filetypes=(("Text files", "*.txt"), ("Pem files", "*.pem"), ("Clavis Files", "*.clavis"), ("All files", "*.*"))
        )
        if file_path:  # If a file was selected
            label.config(text=f"Selected File: {file_path}")
            selected_file.set(file_path)
            show_buttons()
        else:
            label.config(text="No file selected.")
            hide_buttons()
    select_button = tk.Button(root, text="Select File", command=select_file)
    select_button.pack(pady=20)

    # Create a label to display the selected file path
    label = tk.Label(root, text="No file selected.")
    label.pack()



    # ------------- Function choosing --------------- #

    buttons_frame = tk.Frame(root)
    buttons_frame.pack(anchor="w", pady=10, padx=10)

    func_var = tk.IntVar()

    if Algorithm.KEY_GENERATION in selected_alg.implements:
        key_gen_button = tk.Radiobutton(buttons_frame,
                                        text="Generate Key",
                                        font=(FONT, 30),
                                        variable=func_var,
                                        value=0,
                                        padx=10,
                                        bg=BG_COLOR_2,
                                        activebackground=FG_COLOR,
                                        )
        key_gen_button.pack(side=tk.LEFT)

    if Algorithm.ENCRYPTION in selected_alg.implements:
        encrypt_button = tk.Radiobutton(buttons_frame,
                                        text="Encrypt",
                                        font=(FONT, 30),
                                        variable=func_var,
                                        value=1,
                                        padx=50,
                                        bg=BG_COLOR_2,
                                        activebackground=FG_COLOR,
                                        )
        buttons.append(encrypt_button)
    if Algorithm.DECRYPTION in selected_alg.implements:
        decrypt_button = tk.Radiobutton(buttons_frame,
                                        text="Decrypt",
                                        font=(FONT, 30),
                                        variable=func_var,
                                        value=2,
                                        padx=50,
                                        bg=BG_COLOR_2,
                                        activebackground=FG_COLOR,
                                        )
        buttons.append(decrypt_button)
    if Algorithm.SIGNATURE in selected_alg.implements:
        sig_button = tk.Radiobutton(buttons_frame,
                                    text="Signature",
                                    font=(FONT, 30),
                                    variable=func_var,
                                    value=3,
                                    padx=50,
                                    bg=BG_COLOR_2,
                                    activebackground=FG_COLOR,
                                    )
        buttons.append(sig_button)
    if Algorithm.VERIFICATION in selected_alg.implements:
        ver_button = tk.Radiobutton(buttons_frame,
                                    text="Verify",
                                    font=(FONT, 30),
                                    variable=func_var,
                                    value=4,
                                    padx=50,
                                    bg=BG_COLOR_2,
                                    activebackground=FG_COLOR,
                                    )
        buttons.append(ver_button)

    # -------------- Mainloop call ------------------ #
    root.mainloop()
