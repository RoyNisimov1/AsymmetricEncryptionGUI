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

    def __init__(self):
        FONT = "Ariel"

        # -------------- Initialise window --------------- #
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root = ctk.CTk()
        self.root.title("Clavis")
        self.root.geometry()
        icon_loc = "Assets/Clavis.ico"
        self.root.iconbitmap(icon_loc)

        self.root.update_idletasks()

        self.root.after(0, lambda: self.root.state('zoomed'))

        def load_key(location, password=b""):
            try:
                return selected_alg.load_key(location, password=password,
                                             func=lambda msg, key: AESWrapper.decrypt(
                                                 AESWrapper.generate_key(password=password, salt=key), msg))
            except Exception as e:
                messagebox.showinfo("Error!", f"Exception '{e}' occurred. Can not load key! Check the password field or the algorithem type")
            return None

        # -------------- Algorithm choosing widgets -------------- #
        selector_frame = ctk.CTkFrame(self.root)
        selector_frame.pack()
        algs_titles = [alg.name for alg in Global().algorithms]
        algs_selector = RadiobuttonManager(selector_frame, algs_titles)
        algs_selector.pack()

        selected_alg = Global().algorithms[algs_selector.chosen_alg_index.get()]

        # ------------- Select keyfile ------------------ #
        buttons = []

        def show_buttons():
            for button in buttons:
                button.pack(side=tk.LEFT, padx=20)

        def hide_buttons():
            for button in buttons:
                button.pack_forget()
            show_key_gen_frame()
            func_var.set(0)

        file_locator = FileLocator(self.root, on_path_found=show_buttons, on_path_not_found=hide_buttons,
                                   text="Select key file")
        file_locator.pack()

        # ------------- Function choosing --------------- #

        buttons_frame = ctk.CTkFrame(self.root)
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
        key_gen_frame = ctk.CTkFrame(self.root)
        encrypt_frame = ctk.CTkFrame(self.root)
        decrypt_frame = ctk.CTkFrame(self.root)
        signature_frame = ctk.CTkFrame(self.root)
        verify_frame = ctk.CTkFrame(self.root)

        # ------------- key gen frame ------------------ #

        show_key_gen_frame()
        priv, pub = None, None

        generate_label = ctk.CTkLabel(key_gen_frame, text="Generating keys")

        def gen_keys_thread_task():
            global priv, pub
            priv, pub = selected_alg.generate_key(int(key_size.get()))
            priv_loc = os.path.join(dirSelector.path, "priv.clavis")
            pub_loc = os.path.join(dirSelector.path, "pub.clavis")

            password = password_entry.get_value()

            selected_alg.export(priv, priv_loc, password.encode('utf-8'), lambda msg, key: AESWrapper.encrypt(
                AESWrapper.generate_key(password=password, salt=key), msg))

            selected_alg.export(pub, pub_loc, b"", lambda msg, key: AESWrapper.encrypt(
                AESWrapper.generate_key(password=b"", salt=key), msg))

            generate_button.configure(state="normal")
            dirSelector.enable()
            password_entry.enable()
            generate_label.configure(text="Generated!")
            self.root.after(1000, lambda: generate_label.pack_forget())

        def generate_keys():
            global priv, pub
            key_gen_thread = threading.Thread(daemon=True, target=gen_keys_thread_task)
            key_gen_thread.start()
            generate_label.configure(text="Generating keys")
            generate_label.pack()
            generate_button.configure(state="disabled")
            dirSelector.disable()
            password_entry.disable()

        ctk.CTkLabel(key_gen_frame, text="Key Size: ").pack()

        key_size = ctk.StringVar()
        key_size.set("1024")
        combobox = ctk.CTkComboBox(master=key_gen_frame,
                                   values=["1024", "2048", "3072", "4096"],
                                   command=lambda choice: key_size.set(choice))
        combobox.pack(pady=20)
        combobox.set("1024")
        combobox.configure(state="readonly")

        generate_button = ctk.CTkButton(key_gen_frame, command=generate_keys, text="Generate", state="disabled")
        generate_button.pack(pady=25)

        password_entry = EntryBox(key_gen_frame, text="Password: ")
        password_entry.pack()

        dirSelector = FileLocator(master=key_gen_frame, search_type=FileLocator.SAVE_DIR, text="Select save directory",
                                  on_path_found=lambda: generate_button.configure(state="normal"),
                                  on_path_not_found=lambda: generate_button.configure(state="disabled"))
        dirSelector.pack()

        # ------------- encrypt gen frame ------------------ #

        class EncryptFrame:
            def __init__(self):
                self.from_file_frame = ctk.CTkFrame(encrypt_frame)

                self.not_from_file_frame = ctk.CTkFrame(encrypt_frame)

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
                        self.password_entry = EntryBox(not_from_file_frame, "Key password: ")
                        self.password_entry.pack()

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
                            key = load_key(file_locator.path, self.password_entry.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            data = self.msg_entry.get_value().encode("utf-8")
                            cipher = selected_alg.Encrypt(data, key, b"")
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

                        self.save_loc = FileLocator(not_from_file_frame, FileLocator.SAVE_FILE, text="Select save file location")
                        self.save_loc.pack()

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            not_from_file_frame.clipboard_clear()
                            not_from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(not_from_file_frame, text="Copy output", command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                NotFromFileClass(self.not_from_file_frame)

                # ------------------ if from file is selected ----------------- #

                class FromFileClass:

                    def __init__(self, from_file_frame):
                        self.password_entry = EntryBox(from_file_frame, "Key password: ")
                        self.password_entry.pack()

                        self.from_file_asker = FileLocator(from_file_frame, text="File to encrypt",
                                                      on_path_not_found=lambda: self.encrypt_btn.configure(state="disabled"),
                                                      on_path_found=lambda: self.encrypt_btn.configure(state="normal"))
                        self.from_file_asker.pack()

                        def encrypt_data():
                            key = load_key(file_locator.path, self.password_entry.get_value().encode("utf-8"))
                            if key is None:
                                return ""
                            with open(self.from_file_asker.path, "rb") as f:
                                data = f.read()
                            cipher = selected_alg.Encrypt(data, key, b"")
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

                        self.save_loc = FileLocator(from_file_frame, FileLocator.SAVE_FILE, text="Select save file location")
                        self.save_loc.pack()

                        def copy_output_to_clipboard():
                            text_to_copy = self.output_box.box.get("0.0", tk.END).strip()
                            from_file_frame.clipboard_clear()
                            from_file_frame.clipboard_append(text_to_copy)

                        self.copy_btn = ctk.CTkButton(from_file_frame, text="Copy output", command=copy_output_to_clipboard)
                        self.copy_btn.pack(anchor="e", padx=(10, 20))

                FromFileClass(self.from_file_frame)
        EncryptFrame()

        # ------------- decrypt gen frame ------------------ #

        class DecryptFrame:

            def __init__(self):
                self.from_file_frame = ctk.CTkFrame(decrypt_frame)

                self.not_from_file_frame = ctk.CTkFrame(decrypt_frame)

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

                    self.password_entry = EntryBox(not_from_file_frame, "Password: ")
                    self.password_entry.pack()

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
                        key = load_key(file_locator.path, self.password_entry.get_value().encode("utf-8"))
                        if key is None:
                            return ""
                        data = self.msg_entry.get_value()
                        if not key.has_private:
                            messagebox.showinfo(title="Error", message="The selected key is public! can not decrypt!")
                            return ""
                        try:
                            msg = selected_alg.Decrypt(data, key, b"")
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

                    self.copy_btn = ctk.CTkButton(not_from_file_frame, text="Copy output", command=copy_output_to_clipboard)
                    self.copy_btn.pack(anchor="e", padx=(10, 20))




            class FromFileSelected:

                def __init__(self, from_file_frame):
                    self.password_entry = EntryBox(from_file_frame, "Key password: ")
                    self.password_entry.pack()

                    self.from_file_asker = FileLocator(from_file_frame, text="File to Decrypt",
                                                       on_path_not_found=lambda: self.decrypt_btn.configure(
                                                           state="disabled"),
                                                       on_path_found=lambda: self.decrypt_btn.configure(state="normal"))
                    self.from_file_asker.pack()

                    def decrypt_data():
                        key = load_key(file_locator.path, self.password_entry.get_value().encode("utf-8"))
                        if key is None:
                            return ""
                        with open(self.from_file_asker.path, "rb") as f:
                            data = f.read()
                        cipher = selected_alg.Decrypt(data, key, b"")
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

        # ------------- sign gen frame ------------------ #

        # ------------- verify gen frame ------------------ #

    def mainloop(self, *args, **kwargs):
        self.root.mainloop(*args, **kwargs)
