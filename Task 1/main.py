#!/usr/bin/env python3


import argparse
import tkinter as tk
from tkinter import messagebox, ttk


BASIC_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ADVANCED_ALPHABET = "".join(chr(i) for i in range(32, 127))


def vigenere_encrypt_basic(plaintext, key):
    key = key.upper()
    ciphertext = []
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            plaintext_index = ord(char.upper()) - ord("A")
            key_index_value = ord(key[key_index % len(key)]) - ord("A")
            cipher_index = (plaintext_index + key_index_value) % len(BASIC_ALPHABET)
            ciphertext.append(chr(base + cipher_index))
            key_index += 1
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def vigenere_decrypt_basic(ciphertext, key):
    key = key.upper()
    plaintext = []
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            cipher_index = ord(char.upper()) - ord("A")
            key_index_value = ord(key[key_index % len(key)]) - ord("A")
            plaintext_index = (cipher_index - key_index_value) % len(BASIC_ALPHABET)
            plaintext.append(chr(base + plaintext_index))
            key_index += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)


def vigenere_encrypt_advanced(plaintext, key):
    ciphertext = []
    key_index = 0
    for char in plaintext:
        if 32 <= ord(char) <= 126:
            plaintext_index = ADVANCED_ALPHABET.index(char)
            key_char = key[key_index % len(key)]
            key_index_value = ADVANCED_ALPHABET.index(key_char)
            cipher_index = (plaintext_index + key_index_value) % len(ADVANCED_ALPHABET)
            ciphertext.append(ADVANCED_ALPHABET[cipher_index])
            key_index += 1
        else:
            ciphertext.append(char)
    return "".join(ciphertext)


def vigenere_decrypt_advanced(ciphertext, key):
    plaintext = []
    key_index = 0
    for char in ciphertext:
        if 32 <= ord(char) <= 126:
            cipher_index = ADVANCED_ALPHABET.index(char)
            key_char = key[key_index % len(key)]
            key_index_value = ADVANCED_ALPHABET.index(key_char)
            plaintext_index = (cipher_index - key_index_value) % len(ADVANCED_ALPHABET)
            plaintext.append(ADVANCED_ALPHABET[plaintext_index])
            key_index += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)


def validate_key(mode, key):
    if not key:
        raise ValueError("Key cannot be empty.")

    if mode == "basic" and not key.isalpha():
        raise ValueError("Basic mode requires a key made of letters only.")

    if mode == "advanced":
        if any(not 32 <= ord(char) <= 126 for char in key):
            raise ValueError("Advanced mode requires ASCII characters from 32 to 126 in the key.")


def transform_text(mode, text, key, operation):
    validate_key(mode, key)

    if mode == "basic":
        if operation == "encrypt":
            return vigenere_encrypt_basic(text, key)
        return vigenere_decrypt_basic(text, key)

    if operation == "encrypt":
        return vigenere_encrypt_advanced(text, key)
    return vigenere_decrypt_advanced(text, key)


class VigenereApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vigenere Cipher System")
        self.root.geometry("780x560")
        self.root.minsize(680, 500)

        self.mode_var = tk.StringVar(value="basic")
        self.key_var = tk.StringVar()
        self.status_var = tk.StringVar(
            value="Enter text and a key, then choose Encrypt or Decrypt."
        )

        self._configure_style()
        self._build_layout()

    def _configure_style(self):
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Hint.TLabel", foreground="#4b5563")

    def _build_layout(self):
        frame = ttk.Frame(self.root, padding=16)
        frame.grid(sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)

        ttk.Label(frame, text="Vigenere Cipher", style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )

        controls = ttk.Frame(frame)
        controls.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 12))
        controls.columnconfigure(4, weight=1)

        ttk.Label(controls, text="Mode").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            controls, text="Basic", value="basic", variable=self.mode_var
        ).grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Radiobutton(
            controls, text="Advanced", value="advanced", variable=self.mode_var
        ).grid(row=0, column=2, sticky="w", padx=(10, 0))
        ttk.Label(controls, text="Key").grid(row=0, column=3, sticky="e", padx=(16, 8))
        ttk.Entry(controls, textvariable=self.key_var).grid(row=0, column=4, sticky="ew")

        input_frame = ttk.LabelFrame(frame, text="Input")
        output_frame = ttk.LabelFrame(frame, text="Output")
        input_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 8))
        output_frame.grid(row=2, column=1, sticky="nsew", padx=(8, 0))

        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        self.input_text = tk.Text(
            input_frame,
            wrap="word",
            font=("Consolas", 11),
            height=12,
            background="#ffffff",
            foreground="#111827",
            relief="flat",
        )
        self.output_text = tk.Text(
            output_frame,
            wrap="word",
            font=("Consolas", 11),
            height=12,
            background="#f8fafc",
            foreground="#111827",
            relief="flat",
            cursor="arrow",
        )
        self.output_text.bind("<Key>", lambda _event: "break")

        self.input_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.output_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 8))
        buttons.columnconfigure(4, weight=1)

        ttk.Button(buttons, text="Encrypt", command=lambda: self.process("encrypt")).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(buttons, text="Decrypt", command=lambda: self.process("decrypt")).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(buttons, text="Swap", command=self.swap_text).grid(
            row=0, column=2, padx=(0, 8)
        )
        ttk.Button(buttons, text="Clear", command=self.clear_fields).grid(row=0, column=3)

        ttk.Label(frame, textvariable=self.status_var, style="Hint.TLabel").grid(
            row=4, column=0, columnspan=2, sticky="w"
        )

    def process(self, operation):
        input_text = self.input_text.get("1.0", "end-1c")
        key = self.key_var.get()
        mode = self.mode_var.get()

        try:
            result = transform_text(mode, input_text, key, operation)
        except ValueError as error:
            self._set_output_text("")
            self.status_var.set(str(error))
            messagebox.showerror("Invalid input", str(error), parent=self.root)
            return

        self._set_output_text(result)
        action = "Encrypted" if operation == "encrypt" else "Decrypted"
        self.status_var.set(f"{action} text using {mode} mode.")

    def swap_text(self):
        output_text = self.output_text.get("1.0", "end-1c")
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", output_text)
        self._set_output_text("")
        self.status_var.set("Moved the output back into the input box.")

    def clear_fields(self):
        self.input_text.delete("1.0", "end")
        self._set_output_text("")
        self.key_var.set("")
        self.status_var.set("Cleared the text boxes and key.")

    def _set_output_text(self, value):
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", value)


def run_cli():
    print("Vigenere Cipher System")
    mode = input("Choose mode (basic/advanced): ").strip().lower()
    if mode not in {"basic", "advanced"}:
        print("Invalid mode. Choose 'basic' or 'advanced'.")
        return

    plaintext = input("Enter plaintext: ")
    key = input("Enter key: ")

    try:
        ciphertext = transform_text(mode, plaintext, key, "encrypt")
        decrypted = transform_text(mode, ciphertext, key, "decrypt")
    except ValueError as error:
        print(error)
        return

    print(f"Encrypted: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    if decrypted == plaintext:
        print("Decryption successful!")
    else:
        print("Decryption failed.")


def run_gui():
    root = tk.Tk()
    VigenereApp(root)
    root.mainloop()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Vigenere cipher tool with a desktop GUI and CLI fallback."
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run the terminal version instead of the desktop window.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.cli:
        run_cli()
        return

    try:
        run_gui()
    except tk.TclError as error:
        print(f"Unable to start the GUI: {error}")
        print("Falling back to the command-line interface.")
        run_cli()


if __name__ == "__main__":
    main()
