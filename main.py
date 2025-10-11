import os.path
import threading
import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk

from Algorithms.AESWrapper import AESWrapper
from Components.entry_box import entry_box
from Global import Global
from Algorithms.Algorithm import Algorithm
from Components.file_locator import FileLocator

if __name__ == "__main__":
    FONT = "Ariel"

    # -------------- Initialise window --------------- #
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    root.title("Clavis")
    root.geometry()
    icon_loc = "Assets/Clavis.ico"
    root.iconbitmap(icon_loc)

    root.update_idletasks()

    key_gen_frame = ctk.CTkFrame(root)
    encrypt_frame = ctk.CTkFrame(root)
    decrypt_frame = ctk.CTkFrame(root)
    signature_frame = ctk.CTkFrame(root)
    verify_frame = ctk.CTkFrame(root)


    # -------------- Algorithm choosing widgets -------------- #
    alg_frame = ctk.CTkFrame(root)
    alg_frame.pack(pady=10, anchor="w")
    chosen_alg_index = ctk.IntVar()
    alg_buttons = []
    for index, alg in enumerate(Global().algorithms):
        radiobutton = ctk.CTkRadioButton(alg_frame,
                                     text=alg.name,
                                     font=(FONT, 30),
                                     variable=chosen_alg_index,
                                     value=index,
                                         )
        alg_buttons.append(radiobutton)
        radiobutton.pack(side=tk.LEFT, padx=10, pady=10)
    selected_alg = Global().algorithms[chosen_alg_index.get()]

    # ------------- Select keyfile ------------------ #
    selected_file = ctk.StringVar()

    buttons = []
    def show_buttons():
        for button in buttons:
            button.pack(side=tk.LEFT, padx=20)

    def hide_buttons():
        for button in buttons:
            button.pack_forget()
        func_var.set(0)

    file_locator = FileLocator(root, on_path_found=show_buttons, on_path_not_found=hide_buttons, text="Select key file")
    file_locator.pack()

    # ------------- Function choosing --------------- #

    buttons_frame = ctk.CTkFrame(root)
    buttons_frame.pack(anchor="w", pady=10, padx=10)

    func_var = tk.IntVar()

    def hide_widgets():
        key_gen_frame.pack_forget()
        encrypt_frame.pack_forget()
        decrypt_frame.pack_forget()
        signature_frame.pack_forget()
        verify_frame.pack_forget()

    def show_key_gen_frame():
        hide_widgets()
        key_gen_frame.pack(expand=True, fill="both")

    def show_encrypt_frame():
        hide_widgets()
        encrypt_frame.pack(expand=True, fill="both")

    def show_decrypt_frame():
        hide_widgets()
        decrypt_frame.pack(expand=True, fill="both")

    def show_signature_frame():
        hide_widgets()
        signature_frame.pack(expand=True, fill="both")

    def show_verify_frame():
        hide_widgets()
        verify_frame.pack(expand=True, fill="both")


    if Algorithm.KEY_GENERATION in selected_alg.implements:
        key_gen_button = ctk.CTkRadioButton(buttons_frame,
                                        text="Generate Key",
                                        font=(FONT, 30),
                                        variable=func_var,
                                        value=0,
                                        command=show_key_gen_frame
                                        )
        key_gen_button.pack(side=tk.LEFT, padx=20)
    if Algorithm.ENCRYPTION in selected_alg.implements:
        encrypt_button = ctk.CTkRadioButton(buttons_frame,
                                        text="Encrypt",
                                        font=(FONT, 30),
                                        variable=func_var,
                                        value=1,
    
                                        command=show_encrypt_frame
                                        )
        buttons.append(encrypt_button)
    if Algorithm.DECRYPTION in selected_alg.implements:
        decrypt_button = ctk.CTkRadioButton(buttons_frame,
                                        text="Decrypt",
                                        font=(FONT, 30),
                                        variable=func_var,
                                        value=2,
    
                                        command=show_decrypt_frame
                                        )
        buttons.append(decrypt_button)
    if Algorithm.SIGNATURE in selected_alg.implements:
        sig_button = ctk.CTkRadioButton(buttons_frame,
                                    text="Signature",
                                    font=(FONT, 30),
                                    variable=func_var,
                                    value=3,

                                    command=show_signature_frame
                                    )
        buttons.append(sig_button)
    if Algorithm.VERIFICATION in selected_alg.implements:
        ver_button = ctk.CTkRadioButton(buttons_frame,
                                    text="Verify",
                                    font=(FONT, 30),
                                    variable=func_var,
                                    value=4,
                                    command=show_verify_frame
                                    )
        buttons.append(ver_button)

    # ------------- key gen frame ------------------ #

    show_key_gen_frame()
    priv, pub = None, None

    generate_label = ctk.CTkLabel(key_gen_frame, text="Generating keys")


    def gen_keys_thread_task():
        global priv, pub
        priv, pub = selected_alg.generate_key(1024)
        priv_loc = os.path.join(dirSelector.path, "priv.clavis")
        pub_loc = os.path.join(dirSelector.path, "pub.clavis")

        password = password_entry.get_value()
        priv.export(file_name=priv_loc, pwd=password.encode('utf-8'), enc_func=lambda msg, key: AESWrapper.encrypt(AESWrapper.generate_key(password=password, salt=key), msg))
        pub.export(file_name=pub_loc, pwd=b"", enc_func=lambda msg, key: AESWrapper.encrypt(AESWrapper.generate_key(salt=key), msg))

        generate_button.configure(state="normal")
        dirSelector.enable()
        password_entry.enable()
        generate_label.configure(text="Generated!")
        root.after(1000, lambda: generate_label.pack_forget())


    def generate_keys():
        global priv, pub
        key_gen_thread = threading.Thread(daemon=True, target=gen_keys_thread_task)
        key_gen_thread.start()
        generate_label.configure(text="Generating keys")
        generate_label.pack()
        generate_button.configure(state="disabled")
        dirSelector.disable()
        password_entry.disable()





    generate_button = ctk.CTkButton(key_gen_frame, command=generate_keys, text="Generate", state="disabled")
    generate_button.pack(pady=25)

    password_entry = entry_box(key_gen_frame, text="Password: ")
    password_entry.pack()



    dirSelector = FileLocator(master=key_gen_frame, search_type=FileLocator.SAVE_DIR, text="Select save directory", on_path_found=lambda : generate_button.configure(state="normal"), on_path_not_found=lambda : generate_button.configure(state="disabled"))
    dirSelector.pack()







    root.after(0, lambda: root.state('zoomed'))
    # -------------- Mainloop call ------------------ #
    root.mainloop()
