import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk

from Global import Global


class FileLocator:

    OPEN_FILE = "open-file"
    SAVE_FILE = "save-file"
    SAVE_DIR = "save-DIR"

    def __init__(self, master, search_type="", on_path_found=lambda: None, on_path_not_found=lambda: None, text="Select path"):
        self.on_path_not_found = on_path_not_found
        self.on_path_found = on_path_found
        self.path = ""
        if search_type == "":
            search_type = FileLocator.OPEN_FILE
        self.search_type = search_type
        self.text = text
        self.master = master

        self.frame = ctk.CTkFrame(self.master, fg_color=("#D9D9D9", "#2B2B2B"))

        self.select_button = ctk.CTkButton(self.frame, text=self.text, command=self.create_func(), font=Global().font)
        self.select_button.grid(row=0, column=0, padx=(10, 10))

        # Create a label to display the selected file path
        self.label = ctk.CTkLabel(self.frame, text="No path selected.")
        self.label.grid(row=0, column=1)

    def disable(self):
        self.select_button.configure(state="disabled")

    def enable(self):
        self.select_button.configure(state="normal")

    def create_func(self):

        if self.search_type == FileLocator.OPEN_FILE:
            return self.select_file
        if self.search_type == FileLocator.SAVE_DIR:
            return self.select_save_directory
        if self.search_type == FileLocator.SAVE_FILE:
            return self.select_save_file

        return lambda: None

    def select_save_file(self):
        file_path = tk.filedialog.asksaveasfilename(
            title="Select a File",
            initialdir="/",
            filetypes=(("text file", "*.txt"), ("All files", "*.*"))
        )
        self.path = file_path
        if file_path:  # If a file was selected
            self.label.configure(text=f"Selected File: {file_path}")
            self.on_path_found()
        else:
            self.label.configure(text="No file selected.")
            self.on_path_not_found()



    def select_file(self):
        file_path = tk.filedialog.askopenfilename(
            title="Select a File",
            initialdir="/",
            filetypes=(("Clavis Files", "*.clavis"), ("All files", "*.*"))
        )
        self.path = file_path
        if file_path:  # If a file was selected
            self.label.configure(text=f"Selected File: {file_path}")
            self.on_path_found()
        else:
            self.label.configure(text="No file selected.")
            self.on_path_not_found()

    def select_save_directory(self):
        selected_directory_v = filedialog.askdirectory(
            title="Select Save Directory",
            initialdir="/"
        )
        self.path = selected_directory_v
        if selected_directory_v:
            self.label.configure(text=f"{selected_directory_v}")
            self.on_path_found()
        else:
            self.label.configure(text="No directory was selected")
            self.on_path_not_found()



    def pack(self, **kwargs):
        self.frame.pack(**kwargs)

    def pack_forget(self):
        self.frame.pack_forget()

