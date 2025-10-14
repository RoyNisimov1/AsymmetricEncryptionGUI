import os.path
import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

from Algorithms.AESWrapper import AESWrapper
from Components.entry_box import EntryBox
from Components.textbox_area import TextBoxArea
from Global import Global
from Algorithms.Algorithm import Algorithm
from Components.file_locator import FileLocator
from Components.Radiobutton_manager import RadiobuttonManager


class APP:
    frame_color = ("#D9D9D9", "#2B2B2B")

    def __init__(self):
        FONT = "Ariel"

        # -------------- Initialise window --------------- #
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        self.root = ctk.CTk()
        self.root.title("Clavis")
        self.root.geometry()
        self.root.configure(fg_color=APP.frame_color)
        icon_loc = "Assets/Clavis.ico"
        self.root.iconbitmap(icon_loc)

        self.root.update_idletasks()

        self.root.after(0, lambda: self.root.state('zoomed'))

        def load_key(location, password=b""):
            try:
                return Global().selected_alg.load_key(location, password=password,
                                             func=lambda msg, key: AESWrapper.decrypt(
                                                 AESWrapper.generate_key(password=password, salt=key), msg))
            except Exception as e:
                messagebox.showinfo("Error!",
                                    f"Exception '{e}' occurred. Can not load key! Check the password field or the algorithem type")
            return None

        # -------------- Algorithm choosing widgets -------------- #
        buttons = []
        selector_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)
        selector_frame.pack()
        algs_titles = [alg.name for alg in Global().algorithms]
        Global().selected_alg = Global().algorithms[0]

        def show_btn_wrapper():
            Global().selected_alg = Global().algorithms[algs_selector.chosen_alg_index.get()]
            if file_locator.path:
                show_buttons()

        algs_selector = RadiobuttonManager(selector_frame, algs_titles, command=show_btn_wrapper)
        algs_selector.pack()

        Global().selected_alg = Global().algorithms[algs_selector.chosen_alg_index.get()]

        # ------------- Select keyfile ------------------ #

        def show_buttons():
            for button in buttons:
                button.pack_forget()
            buttons.clear()
            if Algorithm.ENCRYPTION in Global().selected_alg.implements:
                encrypt_button = ctk.CTkRadioButton(buttons_frame,
                                                    text="Encrypt",
                                                    font=(FONT, 30),
                                                    variable=func_var,
                                                    value=1,

                                                    command=show_encrypt_frame
                                                    )
                buttons.append(encrypt_button)
            if Algorithm.DECRYPTION in Global().selected_alg.implements:
                decrypt_button = ctk.CTkRadioButton(buttons_frame,
                                                    text="Decrypt",
                                                    font=(FONT, 30),
                                                    variable=func_var,
                                                    value=2,

                                                    command=show_decrypt_frame
                                                    )
                buttons.append(decrypt_button)
            if Algorithm.SIGNATURE in Global().selected_alg.implements:
                sig_button = ctk.CTkRadioButton(buttons_frame,
                                                text="Signature",
                                                font=(FONT, 30),
                                                variable=func_var,
                                                value=3,

                                                command=show_signature_frame
                                                )
                buttons.append(sig_button)
            if Algorithm.VERIFICATION in Global().selected_alg.implements:
                ver_button = ctk.CTkRadioButton(buttons_frame,
                                                text="Verify",
                                                font=(FONT, 30),
                                                variable=func_var,
                                                value=4,
                                                command=show_verify_frame
                                                )
                buttons.append(ver_button)
            for i, button in enumerate(buttons):
                button.pack(side=tk.LEFT, padx=20)

        def hide_buttons():
            for button in buttons:
                button.pack_forget()
            buttons.clear()
            show_key_gen_frame()
            func_var.set(0)

        file_locator = FileLocator(self.root, on_path_found=show_buttons, on_path_not_found=hide_buttons,
                                   text="Select key file")
        file_locator.pack()

        Global().set_root(self.root)
        Global().init_password_field()

        # ------------- Function choosing --------------- #

        buttons_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)
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

        if Algorithm.KEY_GENERATION in Global().selected_alg.implements:
            key_gen_button = ctk.CTkRadioButton(buttons_frame,
                                                text="Generate Key",
                                                font=(FONT, 30),
                                                variable=func_var,
                                                value=0,
                                                command=show_key_gen_frame
                                                )
            key_gen_button.pack(side=tk.LEFT, padx=20)

        key_gen_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)
        encrypt_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)
        decrypt_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)
        signature_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)
        verify_frame = ctk.CTkFrame(self.root, fg_color=APP.frame_color)

        # ------------- key gen frame ------------------ #

        show_key_gen_frame()
        priv, pub = None, None

        generate_label = ctk.CTkLabel(key_gen_frame, text="")

        def gen_keys_thread_task():
            global priv, pub
            priv, pub = Global().selected_alg.generate_key(int(key_size.get()))
            priv_loc = os.path.join(dirSelector.path, "priv.clavis")
            pub_loc = os.path.join(dirSelector.path, "pub.clavis")

            password = password_entry.get_value()

            Global().selected_alg.export(priv, priv_loc, password.encode('utf-8'), lambda msg, key: AESWrapper.encrypt(
                AESWrapper.generate_key(password=password, salt=key), msg))

            Global().selected_alg.export(pub, pub_loc, b"", lambda msg, key: AESWrapper.encrypt(
                AESWrapper.generate_key(password=b"", salt=key), msg))

            generate_button.configure(state="normal")
            dirSelector.enable()
            password_entry.enable()
            generate_label.configure(text="Generated! ✅")
            self.root.after(1000, lambda: generate_label.configure(text=""))

        def generate_keys():
            global priv, pub
            key_gen_thread = threading.Thread(daemon=True, target=gen_keys_thread_task)
            generate_label.configure(text="Generating keys")
            generate_button.configure(state="disabled")
            dirSelector.disable()
            password_entry.disable()
            key_gen_thread.start()

        ctk.CTkLabel(key_gen_frame, text="Key Size: ").pack()

        key_size = ctk.StringVar()
        key_size.set("1024")
        combobox = ctk.CTkComboBox(master=key_gen_frame,
                                   values=["1024", "2048", "3072", "4096"],
                                   command=lambda choice: key_size.set(choice))
        combobox.pack(pady=20)
        combobox.set("1024")
        combobox.configure(state="readonly")

        password_entry = EntryBox(key_gen_frame, text="Password: ")
        password_entry.pack(pady=10)

        dirSelector = FileLocator(master=key_gen_frame, search_type=FileLocator.SAVE_DIR, text="Select save directory",
                                  on_path_found=lambda: generate_button.configure(state="normal"),
                                  on_path_not_found=lambda: generate_button.configure(state="disabled"))
        dirSelector.pack()

        generate_button = ctk.CTkButton(key_gen_frame, command=generate_keys, text="Generate", state="disabled")
        generate_button.pack(pady=25)

        generate_label.pack()

        # ------------- encrypt gen frame ------------------ #

        class EncryptFrame:
            def __init__(self):
                self.from_file_frame = ctk.CTkFrame(encrypt_frame, fg_color=APP.frame_color)

                self.not_from_file_frame = ctk.CTkFrame(encrypt_frame, fg_color=APP.frame_color)

                def switch_frames():
                    if self.from_file_checkbox.get():
                        self.from_file_frame.pack(fill=tk.X, expand=True, anchor="n")
                        self.not_from_file_frame.pack_forget()
                    else:
                        self.from_file_frame.pack_forget()
                        self.not_from_file_frame.pack(fill=tk.X, expand=True, anchor="n")

                self.from_file_checkbox = ctk.CTkCheckBox(encrypt_frame, text="From file?", command=switch_frames)
                self.from_file_checkbox.pack()
                switch_frames()

                # ------------------ if not from file is selected ----------------- #
                class NotFromFileClass:
                    def __init__(self, not_from_file_frame):

                        def paste_to_msg_box():
                            try:
                                clipboard_content = not_from_file_frame.clipboard_get()
                                self.msg_entry.box.delete("0.0", tk.END)
                                self.msg_entry.box.insert(tk.INSERT, clipboard_content)
                            except tk.TclError:
                                messagebox.showinfo(title="Warning", message="Empty clipboard")
                                return

                        self.paste_btn = ctk.CTkButton(not_from_file_frame, text="Paste", command=paste_to_msg_box)
                        self.paste_btn.pack(anchor="e")

                        self.msg_entry = TextBoxArea(not_from_file_frame, "Message:")
                        self.msg_entry.pack(fill=tk.X, expand=True, anchor="w")

                        def encrypt_data():
                            key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            data = self.msg_entry.get_value().encode("utf-8")
                            cipher = Global().selected_alg.Encrypt(data, key, b"")
                            self.output_box.box.configure(state="normal")
                            self.output_box.box.delete("0.0", "end")
                            self.output_box.box.insert("0.0", cipher)
                            self.output_box.box.configure(state="disabled")
                            if self.save_loc.path != "":
                                with open(self.save_loc.path, "w") as f:
                                    f.write(cipher)
                            return cipher

                        self.output_box = TextBoxArea(not_from_file_frame, text="Output:")
                        self.output_box.box.configure(state="disabled")

                        self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                        self.encrypt_btn = ctk.CTkButton(not_from_file_frame, text="Encrypt", command=encrypt_data)
                        self.encrypt_btn.pack(pady=(10, 10))

                        self.save_loc = FileLocator(not_from_file_frame, FileLocator.SAVE_FILE,
                                                    text="Select save file location")
                        self.save_loc.pack()

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            not_from_file_frame.clipboard_clear()
                            not_from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(not_from_file_frame, text="Copy output",
                                                      command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                NotFromFileClass(self.not_from_file_frame)

                # ------------------ if from file is selected ----------------- #

                class FromFileClass:

                    def __init__(self, from_file_frame):

                        self.from_file_asker = FileLocator(from_file_frame, text="File to encrypt",
                                                           on_path_not_found=lambda: self.encrypt_btn.configure(
                                                               state="disabled"),
                                                           on_path_found=lambda: self.encrypt_btn.configure(
                                                               state="normal"))
                        self.from_file_asker.pack()

                        def encrypt_data():
                            key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            with open(self.from_file_asker.path, "rb") as f:
                                data = f.read()
                            cipher = Global().selected_alg.Encrypt(data, key, b"")
                            self.output_box.box.configure(state="normal")
                            self.output_box.box.delete("0.0", "end")
                            self.output_box.box.insert("0.0", cipher)
                            self.output_box.box.configure(state="disabled")
                            if self.save_loc.path != "":
                                with open(self.save_loc.path, "w") as f:
                                    f.write(cipher)
                            return cipher

                        self.output_box = TextBoxArea(from_file_frame, text="Output:")
                        self.output_box.box.configure(state="disabled")

                        self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                        self.encrypt_btn = ctk.CTkButton(from_file_frame, text="Encrypt", command=encrypt_data)
                        self.encrypt_btn.configure(state="disabled")
                        self.encrypt_btn.pack(pady=(10, 10))

                        self.save_loc = FileLocator(from_file_frame, FileLocator.SAVE_FILE,
                                                    text="Select save file location")
                        self.save_loc.pack()

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            from_file_frame.clipboard_clear()
                            from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(from_file_frame, text="Copy output",
                                                      command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                FromFileClass(self.from_file_frame)

        EncryptFrame()

        # ------------- decrypt gen frame ------------------ #

        class DecryptFrame:

            def __init__(self):
                self.from_file_frame = ctk.CTkFrame(decrypt_frame, fg_color=APP.frame_color)

                self.not_from_file_frame = ctk.CTkFrame(decrypt_frame, fg_color=APP.frame_color)

                self.from_file_checkbox = ctk.CTkCheckBox(decrypt_frame, text="From file?", command=self.switch_frames)
                self.from_file_checkbox.pack()
                self.switch_frames()

                self.FromFileSelected(self.from_file_frame)
                self.FromFileNotSelected(self.not_from_file_frame)

            def switch_frames(self):
                if self.from_file_checkbox.get():
                    self.from_file_frame.pack(fill=tk.X, expand=True, anchor="n")
                    self.not_from_file_frame.pack_forget()
                else:
                    self.from_file_frame.pack_forget()
                    self.not_from_file_frame.pack(fill=tk.X, expand=True, anchor="n")

            class FromFileNotSelected:
                def __init__(self, not_from_file_frame):


                    def paste_to_msg_box():
                        try:
                            clipboard_content = not_from_file_frame.clipboard_get()
                            self.msg_entry.box.delete("0.0", tk.END)
                            self.msg_entry.box.insert(tk.INSERT, clipboard_content)
                        except tk.TclError:
                            messagebox.showinfo(title="Warning", message="Empty clipboard")
                            return

                    self.paste_btn = ctk.CTkButton(not_from_file_frame, text="Paste", command=paste_to_msg_box)
                    self.paste_btn.pack(anchor="e")

                    self.msg_entry = TextBoxArea(not_from_file_frame, "Ciphertext: ")
                    self.msg_entry.pack(fill=tk.X, expand=True, anchor="w")

                    def decrypt_data():
                        key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                        if key is None:
                            return ""
                        data = self.msg_entry.get_value()
                        if not key.has_private:
                            messagebox.showinfo(title="Error", message="The selected key is public! can not decrypt!")
                            return ""
                        try:
                            msg = Global().selected_alg.Decrypt(data, key, b"")
                        except Exception as e:
                            messagebox.showinfo("Error!", "Can not decrypt!")
                            return ""

                        self.output_box.box.configure(state="normal")
                        self.output_box.box.delete("0.0", "end")
                        self.output_box.box.insert("0.0", msg)
                        self.output_box.box.configure(state="disabled")
                        if self.save_loc.path != "":
                            with open(self.save_loc.path, "w") as f:
                                f.write(msg)
                        return msg

                    self.output_box = TextBoxArea(not_from_file_frame, text="Output:")
                    self.output_box.box.configure(state="disabled")

                    self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                    self.decrypt_btn = ctk.CTkButton(not_from_file_frame, text="Decrypt", command=decrypt_data)
                    self.decrypt_btn.pack(pady=(10, 10))

                    self.save_loc = FileLocator(not_from_file_frame, FileLocator.SAVE_FILE,
                                                text="Select save file location")
                    self.save_loc.pack()

                    def copy_output_to_clipboard():
                        text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                        not_from_file_frame.clipboard_clear()
                        not_from_file_frame.clipboard_append(text_to_copy)

                    self.copy_btn = ctk.CTkButton(not_from_file_frame, text="Copy output",
                                                  command=copy_output_to_clipboard)
                    self.copy_btn.pack(anchor="e", padx=(10, 20))

            class FromFileSelected:

                def __init__(self, from_file_frame):


                    self.from_file_asker = FileLocator(from_file_frame, text="File to Decrypt",
                                                       on_path_not_found=lambda: self.decrypt_btn.configure(
                                                           state="disabled"),
                                                       on_path_found=lambda: self.decrypt_btn.configure(state="normal"))
                    self.from_file_asker.pack()

                    def decrypt_data():
                        key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                        if key is None:
                            return ""
                        with open(self.from_file_asker.path, "rb") as f:
                            data = f.read()
                        cipher = Global().selected_alg.Decrypt(data, key, b"")
                        self.output_box.box.configure(state="normal")
                        self.output_box.box.delete("0.0", "end")
                        self.output_box.box.insert("0.0", cipher)
                        self.output_box.box.configure(state="disabled")
                        if self.save_loc.path != "":
                            with open(self.save_loc.path, "w") as f:
                                f.write(cipher)
                        return cipher

                    self.output_box = TextBoxArea(from_file_frame, text="Output:")
                    self.output_box.box.configure(state="disabled")

                    self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                    self.decrypt_btn = ctk.CTkButton(from_file_frame, text="Decrypt", command=decrypt_data)
                    self.decrypt_btn.configure(state="disabled")
                    self.decrypt_btn.pack(pady=(10, 10))

                    self.save_loc = FileLocator(from_file_frame, FileLocator.SAVE_FILE,
                                                text="Select save file location")
                    self.save_loc.pack()

                    def copy_output_to_clipboard():
                        text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                        from_file_frame.clipboard_clear()
                        from_file_frame.clipboard_append(text_to_copy)

                    self.copy_btn = ctk.CTkButton(from_file_frame, text="Copy output", command=copy_output_to_clipboard)
                    self.copy_btn.pack(anchor="e", padx=(10, 20))

        DecryptFrame()

        # ------------- Sign gen frame ------------------ #

        class SignatureFrame:
            def __init__(self):
                self.from_file_frame = ctk.CTkFrame(signature_frame, fg_color=APP.frame_color)

                self.not_from_file_frame = ctk.CTkFrame(signature_frame, fg_color=APP.frame_color)

                def switch_frames():
                    if self.from_file_checkbox.get():
                        self.from_file_frame.pack(fill=tk.X, expand=True, anchor="n")
                        self.not_from_file_frame.pack_forget()
                    else:
                        self.from_file_frame.pack_forget()
                        self.not_from_file_frame.pack(fill=tk.X, expand=True, anchor="n")

                self.from_file_checkbox = ctk.CTkCheckBox(signature_frame, text="From file?", command=switch_frames)
                self.from_file_checkbox.pack()
                switch_frames()

                # ------------------ if not from file is selected ----------------- #
                class NotFromFileClass:
                    def __init__(self, not_from_file_frame):

                        def paste_to_msg_box():
                            try:
                                clipboard_content = not_from_file_frame.clipboard_get()
                                self.msg_entry.box.delete("0.0", tk.END)
                                self.msg_entry.box.insert(tk.INSERT, clipboard_content)
                            except tk.TclError:
                                messagebox.showinfo(title="Warning", message="Empty clipboard")
                                return

                        self.paste_btn = ctk.CTkButton(not_from_file_frame, text="Paste", command=paste_to_msg_box)
                        self.paste_btn.pack(anchor="e")

                        self.msg_entry = TextBoxArea(not_from_file_frame, "Message:")
                        self.msg_entry.pack(fill=tk.X, expand=True, anchor="w")

                        def sign_data():
                            key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            data = self.msg_entry.get_value().encode("utf-8")
                            if not key.has_private:
                                messagebox.showinfo("Key is public", "Key is public therefore we can not sign")
                                return ""
                            signature = Global().selected_alg.Sign(data, key)
                            self.output_box.box.configure(state="normal")
                            self.output_box.box.delete("0.0", "end")
                            self.output_box.box.insert("0.0", signature)
                            self.output_box.box.configure(state="disabled")
                            if self.save_loc.path != "":
                                with open(self.save_loc.path, "w") as f:
                                    f.write(signature)
                            return signature

                        self.output_box = TextBoxArea(not_from_file_frame, text="Output:")
                        self.output_box.box.configure(state="disabled")

                        self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                        self.sign_btn = ctk.CTkButton(not_from_file_frame, text="Sign", command=sign_data)
                        self.sign_btn.pack(pady=(10, 10))

                        self.save_loc = FileLocator(not_from_file_frame, FileLocator.SAVE_FILE,
                                                    text="Select save file location")
                        self.save_loc.pack()

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            not_from_file_frame.clipboard_clear()
                            not_from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(not_from_file_frame, text="Copy output",
                                                      command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                NotFromFileClass(self.not_from_file_frame)

                # ------------------ if from file is selected ----------------- #

                class FromFileClass:

                    def __init__(self, from_file_frame):

                        self.from_file_asker = FileLocator(from_file_frame, text="File to sign",
                                                           on_path_not_found=lambda: self.sign_btn.configure(
                                                               state="disabled"),
                                                           on_path_found=lambda: self.sign_btn.configure(
                                                               state="normal"))
                        self.from_file_asker.pack()

                        def sign_data():
                            key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            with open(self.from_file_asker.path, "rb") as f:
                                data = f.read()
                            signature = Global().selected_alg.Sign(data, key)
                            self.output_box.box.configure(state="normal")
                            self.output_box.box.delete("0.0", "end")
                            self.output_box.box.insert("0.0", signature)
                            self.output_box.box.configure(state="disabled")
                            if self.save_loc.path != "":
                                with open(self.save_loc.path, "w") as f:
                                    f.write(signature)
                            return signature

                        self.output_box = TextBoxArea(from_file_frame, text="Output:")
                        self.output_box.box.configure(state="disabled")

                        self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                        self.sign_btn = ctk.CTkButton(from_file_frame, text="Sign", command=sign_data)
                        self.sign_btn.configure(state="disabled")
                        self.sign_btn.pack(pady=(10, 10))

                        self.save_loc = FileLocator(from_file_frame, FileLocator.SAVE_FILE,
                                                    text="Select save file location")
                        self.save_loc.pack()

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            from_file_frame.clipboard_clear()
                            from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(from_file_frame, text="Copy output",
                                                      command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                FromFileClass(self.from_file_frame)

        SignatureFrame()

        # ------------- Verify gen frame ------------------ #

        class VerifyFrame:
            def __init__(self):
                self.from_file_frame = ctk.CTkFrame(verify_frame, fg_color=APP.frame_color)

                self.not_from_file_frame = ctk.CTkFrame(verify_frame, fg_color=APP.frame_color)

                def switch_frames():
                    if self.from_file_checkbox.get():
                        self.from_file_frame.pack(fill=tk.X, expand=True, anchor="n")
                        self.not_from_file_frame.pack_forget()
                    else:
                        self.from_file_frame.pack_forget()
                        self.not_from_file_frame.pack(fill=tk.X, expand=True, anchor="n")

                self.from_file_checkbox = ctk.CTkCheckBox(verify_frame, text="From file?", command=switch_frames)
                self.from_file_checkbox.pack()
                switch_frames()

                # ------------------ if not from file is selected ----------------- #
                class NotFromFileClass:
                    def __init__(self, not_from_file_frame):

                        def paste_to_msg_box():
                            try:
                                clipboard_content = not_from_file_frame.clipboard_get()
                                self.msg_entry.box.delete("0.0", tk.END)
                                self.msg_entry.box.insert(tk.INSERT, clipboard_content)
                            except tk.TclError:
                                messagebox.showinfo(title="Warning", message="Empty clipboard")
                                return

                        self.paste_btn = ctk.CTkButton(not_from_file_frame, text="Paste", command=paste_to_msg_box)
                        self.paste_btn.pack(anchor="e")

                        self.msg_entry = TextBoxArea(not_from_file_frame, "Message:")
                        self.msg_entry.pack(fill=tk.X, expand=True, anchor="w")

                        def verify_data():
                            key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            data = self.msg_entry.get_value().encode("utf-8")
                            verification = Global().selected_alg.Verify(data, key)
                            self.output_box.box.configure(state="normal")
                            self.output_box.box.delete("0.0", "end")
                            if verification:
                                self.output_box.box.insert("0.0", "Verified successful!")
                            else:
                                self.output_box.box.insert("0.0", "Verification unsuccessful, signature is wrong!")

                            self.output_box.box.configure(state="disabled")
                            return verification

                        self.output_box = TextBoxArea(not_from_file_frame, text="Output:")
                        self.output_box.box.configure(state="disabled")

                        self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                        self.verify_btn = ctk.CTkButton(not_from_file_frame, text="Verify", command=verify_data)
                        self.verify_btn.pack(pady=(10, 10))

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            not_from_file_frame.clipboard_clear()
                            not_from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(not_from_file_frame, text="Copy output",
                                                      command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                NotFromFileClass(self.not_from_file_frame)

                # ------------------ if from file is selected ----------------- #

                class FromFileClass:

                    def __init__(self, from_file_frame):
                        self.password_entry = EntryBox(from_file_frame, "Key password: ")
                        self.password_entry.pack()

                        self.from_file_asker = FileLocator(from_file_frame, text="File to sign",
                                                           on_path_not_found=lambda: self.verify_btn.configure(
                                                               state="disabled"),
                                                           on_path_found=lambda: self.verify_btn.configure(
                                                               state="normal"))
                        self.from_file_asker.pack()

                        def verify_data():
                            key = load_key(file_locator.path, Global().password_field.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            with open(self.from_file_asker.path, "r") as f:
                                data = f.read()
                            verification = Global().selected_alg.Verify(data, key)
                            self.output_box.box.configure(state="normal")
                            self.output_box.box.delete("0.0", "end")
                            if verification:
                                self.output_box.box.insert("0.0", "Verified successful!")
                            else:
                                self.output_box.box.insert("0.0", "Verification unsuccessful, signature is wrong!")

                            self.output_box.box.configure(state="disabled")
                            return verification

                        self.output_box = TextBoxArea(from_file_frame, text="Output:")
                        self.output_box.box.configure(state="disabled")

                        self.output_box.pack(fill=tk.X, expand=True, anchor="w")

                        self.verify_btn = ctk.CTkButton(from_file_frame, text="Verify", command=verify_data)
                        self.verify_btn.configure(state="disabled")
                        self.verify_btn.pack(pady=(10, 10))

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            from_file_frame.clipboard_clear()
                            from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(from_file_frame, text="Copy output",
                                                      command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                FromFileClass(self.from_file_frame)

        VerifyFrame()

    def mainloop(self, *args, **kwargs):
        self.root.mainloop(*args, **kwargs)
