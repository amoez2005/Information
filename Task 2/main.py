#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

CRYPTO_IMPORT_ERROR = None

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError as exc:  # pragma: no cover - import error path
    AES = None
    get_random_bytes = None
    pad = None
    unpad = None
    CRYPTO_IMPORT_ERROR = exc


APP_TITLE = "AES Encryption and Decryption System"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
FILE_DIALOG_TYPES = [("Text files", "*.txt"), ("All files", "*.*")]


def derive_key(secret: str, key_length_bits: int, salt: bytes) -> bytes:
    if not secret.strip():
        raise ValueError("Secret key cannot be empty.")

    return hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=key_length_bits // 8,
    )


def encrypt_text(plaintext: str, secret: str, mode_name: str, key_length_bits: int) -> dict[str, object]:
    if AES is None:
        raise RuntimeError("PyCryptodome is required to use this application.")
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")

    mode_name = mode_name.upper()
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(secret, key_length_bits, salt)
    iv = None
    data = plaintext.encode("utf-8")

    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    elif mode_name == "CBC":
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    elif mode_name == "CFB":
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        ciphertext = cipher.encrypt(data)
    else:
        raise ValueError(f"Unsupported AES mode: {mode_name}")

    return {
        "algorithm": "AES",
        "mode": mode_name,
        "key_length": key_length_bits,
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8") if iv else "",
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_payload(
    payload_text: str,
    secret: str,
    selected_mode: str,
    selected_key_length: int,
) -> tuple[str, dict[str, object]]:
    if AES is None:
        raise RuntimeError("PyCryptodome is required to use this application.")
    if not payload_text.strip():
        raise ValueError("Ciphertext input cannot be empty.")

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Ciphertext input must be the JSON payload produced by this application."
        ) from exc

    mode_name = str(payload.get("mode", selected_mode)).upper()
    key_length_bits = int(payload.get("key_length", selected_key_length))
    salt_text = payload.get("salt")
    ciphertext_text = payload.get("ciphertext")

    if not salt_text or not ciphertext_text:
        raise ValueError("Ciphertext payload is missing the required salt or ciphertext field.")

    salt = base64.b64decode(salt_text)
    key = derive_key(secret, key_length_bits, salt)
    ciphertext = base64.b64decode(ciphertext_text)
    iv_text = payload.get("iv", "")

    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode_name == "CBC":
        if not iv_text:
            raise ValueError("CBC mode requires an IV in the payload.")
        iv = base64.b64decode(iv_text)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode_name == "CFB":
        if not iv_text:
            raise ValueError("CFB mode requires an IV in the payload.")
        iv = base64.b64decode(iv_text)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        plaintext_bytes = cipher.decrypt(ciphertext)
    else:
        raise ValueError(f"Unsupported AES mode: {mode_name}")

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "The decrypted bytes are not valid UTF-8 text. The key may be incorrect, or the file may be corrupted."
        ) from exc

    metadata = {
        "mode": mode_name,
        "key_length": key_length_bits,
    }
    return plaintext, metadata


def format_payload(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2)


def parse_payload_metadata(payload_text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return None

    if "ciphertext" not in payload:
        return None

    metadata: dict[str, object] = {}
    mode_name = payload.get("mode")
    key_length = payload.get("key_length")

    if isinstance(mode_name, str):
        metadata["mode"] = mode_name.upper()
    if isinstance(key_length, int):
        metadata["key_length"] = key_length
    return metadata


class AesApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1180x760")
        self.root.minsize(960, 700)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.operation_var = tk.StringVar(value="Encrypt")
        self.mode_var = tk.StringVar(value="CBC")
        self.key_length_var = tk.StringVar(value="256")
        self.show_key_var = tk.BooleanVar(value=False)
        self.input_label_var = tk.StringVar()
        self.result_label_var = tk.StringVar()
        self.run_button_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready. Enter text, choose settings, and run the selected operation.")

        self._build_ui()
        self._sync_operation_labels()

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        controls = ttk.LabelFrame(self.root, text="Controls", padding=14)
        controls.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        controls.columnconfigure(3, weight=1)

        ttk.Label(controls, text="Operation").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            controls,
            text="Encrypt",
            value="Encrypt",
            variable=self.operation_var,
            command=self._sync_operation_labels,
        ).grid(row=0, column=1, sticky="w", padx=(8, 6))
        ttk.Radiobutton(
            controls,
            text="Decrypt",
            value="Decrypt",
            variable=self.operation_var,
            command=self._sync_operation_labels,
        ).grid(row=0, column=2, sticky="w", padx=6)

        ttk.Label(controls, text="AES mode").grid(row=0, column=3, sticky="e", padx=(10, 6))
        ttk.Combobox(
            controls,
            textvariable=self.mode_var,
            values=("ECB", "CBC", "CFB"),
            state="readonly",
            width=10,
        ).grid(row=0, column=4, sticky="w")

        ttk.Label(controls, text="Key length").grid(row=0, column=5, sticky="e", padx=(12, 6))
        ttk.Combobox(
            controls,
            textvariable=self.key_length_var,
            values=("128", "192", "256"),
            state="readonly",
            width=10,
        ).grid(row=0, column=6, sticky="w")

        ttk.Label(controls, text="Secret key").grid(row=1, column=0, sticky="w", pady=(12, 0))
        self.key_entry = ttk.Entry(controls, show="*", width=56)
        self.key_entry.grid(row=1, column=1, columnspan=4, sticky="ew", pady=(12, 0), padx=(8, 0))
        ttk.Checkbutton(
            controls,
            text="Show key",
            variable=self.show_key_var,
            command=self._toggle_key_visibility,
        ).grid(row=1, column=5, columnspan=2, sticky="w", pady=(12, 0))

        actions = ttk.Frame(controls)
        actions.grid(row=2, column=0, columnspan=7, sticky="ew", pady=(14, 0))
        for column in range(5):
            actions.columnconfigure(column, weight=1)

        ttk.Button(actions, textvariable=self.run_button_var, command=self.run_selected_operation).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(actions, text="Load .txt into input", command=self.load_input_file).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(actions, text="Save result to .txt", command=self.save_result_file).grid(
            row=0, column=2, sticky="ew", padx=6
        )
        ttk.Button(actions, text="Use result as input", command=self.copy_result_to_input).grid(
            row=0, column=3, sticky="ew", padx=6
        )
        ttk.Button(actions, text="Clear", command=self.clear_text_areas).grid(
            row=0, column=4, sticky="ew", padx=(6, 0)
        )

        editors = ttk.Frame(self.root, padding=(12, 0, 12, 0))
        editors.grid(row=1, column=0, sticky="nsew")
        editors.columnconfigure(0, weight=1)
        editors.columnconfigure(1, weight=1)
        editors.rowconfigure(0, weight=1)

        self.input_frame = ttk.LabelFrame(editors, text="Plaintext Input", padding=10)
        self.input_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.input_frame.rowconfigure(0, weight=1)
        self.input_frame.columnconfigure(0, weight=1)

        self.input_text = ScrolledText(self.input_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.input_text.grid(row=0, column=0, sticky="nsew")

        self.result_frame = ttk.LabelFrame(editors, text="Ciphertext Output", padding=10)
        self.result_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self.result_frame.rowconfigure(0, weight=1)
        self.result_frame.columnconfigure(0, weight=1)

        self.result_text = ScrolledText(self.result_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.result_text.grid(row=0, column=0, sticky="nsew")

        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(14, 6))
        status_bar.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 10))

    def _toggle_key_visibility(self) -> None:
        self.key_entry.configure(show="" if self.show_key_var.get() else "*")

    def _sync_operation_labels(self) -> None:
        if self.operation_var.get() == "Encrypt":
            self.input_label_var.set("Plaintext Input")
            self.result_label_var.set("Ciphertext Output")
            self.run_button_var.set("Encrypt Text")
        else:
            self.input_label_var.set("Ciphertext Input")
            self.result_label_var.set("Decrypted Plaintext")
            self.run_button_var.set("Decrypt Text")

        if hasattr(self, "input_frame"):
            self.input_frame.configure(text=self.input_label_var.get())
        if hasattr(self, "result_frame"):
            self.result_frame.configure(text=self.result_label_var.get())

    def _get_text(self, widget: ScrolledText) -> str:
        return widget.get("1.0", "end-1c")

    def _set_text(self, widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)

    def clear_text_areas(self) -> None:
        self._set_text(self.input_text, "")
        self._set_text(self.result_text, "")
        self.status_var.set("Input and result areas were cleared.")

    def copy_result_to_input(self) -> None:
        result = self._get_text(self.result_text)
        if not result:
            messagebox.showwarning(APP_TITLE, "There is no result to copy yet.")
            return

        self._set_text(self.input_text, result)
        self.status_var.set("Result copied into the input area.")
        metadata = parse_payload_metadata(result)
        if metadata:
            self._apply_payload_metadata(metadata)

    def _apply_payload_metadata(self, metadata: dict[str, object]) -> None:
        mode_name = metadata.get("mode")
        key_length = metadata.get("key_length")

        if isinstance(mode_name, str) and mode_name in {"ECB", "CBC", "CFB"}:
            self.mode_var.set(mode_name)
        if isinstance(key_length, int) and key_length in {128, 192, 256}:
            self.key_length_var.set(str(key_length))

    def load_input_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Load text file",
            filetypes=FILE_DIALOG_TYPES,
        )
        if not path:
            return

        file_path = Path(path)
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not read the selected file.\n\n{exc}")
            return

        self._set_text(self.input_text, content)
        metadata = parse_payload_metadata(content)
        if metadata:
            self._apply_payload_metadata(metadata)
            self.status_var.set(f"Loaded ciphertext payload from {file_path.name}. Mode and key length were auto-filled.")
        else:
            self.status_var.set(f"Loaded text from {file_path.name} into the input area.")

    def save_result_file(self) -> None:
        content = self._get_text(self.result_text)
        if not content:
            messagebox.showwarning(APP_TITLE, "There is no result to save yet.")
            return

        path = filedialog.asksaveasfilename(
            title="Save result",
            defaultextension=".txt",
            filetypes=FILE_DIALOG_TYPES,
        )
        if not path:
            return

        file_path = Path(path)
        try:
            file_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not save the file.\n\n{exc}")
            return

        self.status_var.set(f"Saved result to {file_path.name}.")

    def run_selected_operation(self) -> None:
        source_text = self._get_text(self.input_text)
        secret = self.key_entry.get()
        mode_name = self.mode_var.get()
        key_length_bits = int(self.key_length_var.get())

        try:
            if self.operation_var.get() == "Encrypt":
                payload = encrypt_text(source_text, secret, mode_name, key_length_bits)
                self._set_text(self.result_text, format_payload(payload))
                self.status_var.set(
                    f"Encryption complete. AES-{key_length_bits} in {mode_name} mode was used. "
                    "You can now save the ciphertext payload to a .txt file."
                )
            else:
                plaintext, metadata = decrypt_payload(source_text, secret, mode_name, key_length_bits)
                self._set_text(self.result_text, plaintext)
                self._apply_payload_metadata(metadata)
                self.status_var.set(
                    f"Decryption complete. Payload settings were AES-{metadata['key_length']} in {metadata['mode']} mode."
                )
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_TITLE, str(exc))


def show_missing_dependency_error() -> None:
    root = tk.Tk()
    root.withdraw()
    interpreter = sys.executable
    messagebox.showerror(
        APP_TITLE,
        "PyCryptodome is required to run this application.\n\n"
        f"Current interpreter:\n{interpreter}\n\n"
        "Install it for this interpreter with:\n"
        f"\"{interpreter}\" -m pip install -r requirements.txt\n\n"
        "If you are using VS Code, make sure the selected Python interpreter matches the one above.",
    )
    root.destroy()


def main() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        show_missing_dependency_error()
        return

    root = tk.Tk()
    AesApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
