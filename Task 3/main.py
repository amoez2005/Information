#!/usr/bin/env python3

from __future__ import annotations

import json
from math import isqrt
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText


APP_TITLE = "RSA Encryption and Decryption System"
FILE_DIALOG_TYPES = [("Text files", "*.txt"), ("All files", "*.*")]


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    divisor, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return divisor, x, y


def mod_inverse(value: int, modulus: int) -> int:
    divisor, inverse, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValueError("The modular inverse does not exist for the chosen RSA parameters.")
    return inverse % modulus


def is_prime(number: int) -> bool:
    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0 or number % 3 == 0:
        return False

    candidate = 5
    while candidate * candidate <= number:
        if number % candidate == 0 or number % (candidate + 2) == 0:
            return False
        candidate += 6
    return True


def choose_public_exponent(phi_value: int) -> int:
    preferred = 65537
    if preferred < phi_value and gcd(preferred, phi_value) == 1:
        return preferred

    exponent = 3
    while exponent < phi_value:
        if gcd(exponent, phi_value) == 1:
            return exponent
        exponent += 2

    raise ValueError("Could not find a valid public exponent for the chosen primes.")


def factor_semiprime(modulus: int) -> tuple[int, int]:
    if modulus <= 3:
        raise ValueError("n is too small to factor into two useful RSA primes.")

    if modulus % 2 == 0:
        return 2, modulus // 2

    limit = isqrt(modulus)
    candidate = 3
    while candidate <= limit:
        if modulus % candidate == 0:
            return candidate, modulus // candidate
        candidate += 2

    raise ValueError(
        "Could not factor n with the educational trial-division method. "
        "Use smaller classroom-sized primes for this Task 3 app."
    )


def build_rsa_parameters(p_value: int, q_value: int) -> dict[str, int]:
    if not is_prime(p_value):
        raise ValueError("p must be a prime number.")
    if not is_prime(q_value):
        raise ValueError("q must be a prime number.")
    if p_value == q_value:
        raise ValueError("p and q must be different prime numbers.")

    modulus = p_value * q_value
    if modulus <= 255:
        raise ValueError("n = p * q must be greater than 255 so the app can encrypt UTF-8 bytes.")

    phi_value = (p_value - 1) * (q_value - 1)
    public_exponent = choose_public_exponent(phi_value)
    private_exponent = mod_inverse(public_exponent, phi_value)

    return {
        "p": p_value,
        "q": q_value,
        "n": modulus,
        "phi": phi_value,
        "e": public_exponent,
        "d": private_exponent,
    }


def encrypt_plaintext(plaintext: str, p_value: int, q_value: int) -> tuple[dict[str, object], dict[str, int]]:
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")

    parameters = build_rsa_parameters(p_value, q_value)
    data = plaintext.encode("utf-8")

    if max(data) >= parameters["n"]:
        raise ValueError("Every UTF-8 byte must be smaller than n. Choose larger primes.")

    ciphertext = [pow(byte, parameters["e"], parameters["n"]) for byte in data]
    payload = {
        "algorithm": "RSA",
        "complexity_level": "B",
        "encoding": "utf-8",
        "public_key": {
            "n": parameters["n"],
            "e": parameters["e"],
        },
        "ciphertext": ciphertext,
    }
    return payload, parameters


def parse_payload_text(payload_text: str) -> dict[str, object]:
    if not payload_text.strip():
        raise ValueError("Ciphertext payload cannot be empty.")

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise ValueError("Ciphertext input must be the JSON payload produced by this application.") from exc

    if payload.get("algorithm") != "RSA":
        raise ValueError("The payload does not appear to be an RSA payload.")

    public_key = payload.get("public_key")
    ciphertext = payload.get("ciphertext")

    if not isinstance(public_key, dict):
        raise ValueError("The payload is missing the public key.")
    if not isinstance(ciphertext, list) or not ciphertext:
        raise ValueError("The payload is missing the ciphertext list.")

    return payload


def payload_metadata(payload_text: str) -> dict[str, int] | None:
    try:
        payload = parse_payload_text(payload_text)
    except ValueError:
        return None

    public_key = payload["public_key"]
    n_value = public_key.get("n")
    e_value = public_key.get("e")

    if isinstance(n_value, int) and isinstance(e_value, int):
        return {"n": n_value, "e": e_value}
    return None


def decrypt_payload(payload_text: str) -> tuple[str, dict[str, int]]:
    payload = parse_payload_text(payload_text)
    public_key = payload["public_key"]
    ciphertext = payload["ciphertext"]

    n_value = public_key.get("n")
    e_value = public_key.get("e")
    encoding = payload.get("encoding", "utf-8")

    if not isinstance(n_value, int) or not isinstance(e_value, int):
        raise ValueError("The payload public key must contain integer n and e values.")
    if encoding != "utf-8":
        raise ValueError("This educational app currently expects utf-8 encoded payloads.")

    if not all(isinstance(item, int) and item >= 0 for item in ciphertext):
        raise ValueError("Ciphertext values must be non-negative integers.")

    p_value, q_value = factor_semiprime(n_value)
    parameters = build_rsa_parameters(p_value, q_value)

    if parameters["n"] != n_value or parameters["e"] != e_value:
        if gcd(e_value, parameters["phi"]) != 1:
            raise ValueError("The public exponent e is not valid for the recovered phi value.")
        parameters["e"] = e_value
        parameters["d"] = mod_inverse(e_value, parameters["phi"])

    decrypted_values = [pow(item, parameters["d"], parameters["n"]) for item in ciphertext]
    if any(value < 0 or value > 255 for value in decrypted_values):
        raise ValueError("Decryption produced values outside the byte range.")

    try:
        plaintext = bytes(decrypted_values).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted bytes are not valid UTF-8 text.") from exc

    return plaintext, parameters


def format_payload(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2)


class RsaApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1260x860")
        self.root.minsize(1020, 760)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.p_var = tk.StringVar()
        self.q_var = tk.StringVar()
        self.n_var = tk.StringVar(value="-")
        self.phi_var = tk.StringVar(value="-")
        self.e_var = tk.StringVar(value="-")
        self.d_var = tk.StringVar(value="-")
        self.status_var = tk.StringVar(
            value="Ready. Enter p, q, and plaintext to encrypt, or load a saved RSA payload to decrypt."
        )

        self._build_ui()

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        params = ttk.LabelFrame(self.root, text="RSA Parameters", padding=14)
        params.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        for column in range(8):
            params.columnconfigure(column, weight=1)

        ttk.Label(params, text="Prime p").grid(row=0, column=0, sticky="w")
        ttk.Entry(params, textvariable=self.p_var).grid(row=0, column=1, sticky="ew", padx=(6, 12))

        ttk.Label(params, text="Prime q").grid(row=0, column=2, sticky="w")
        ttk.Entry(params, textvariable=self.q_var).grid(row=0, column=3, sticky="ew", padx=(6, 12))

        ttk.Label(params, text="n = p * q").grid(row=0, column=4, sticky="w")
        ttk.Entry(params, textvariable=self.n_var, state="readonly").grid(row=0, column=5, sticky="ew", padx=(6, 12))

        ttk.Label(params, text="Phi").grid(row=0, column=6, sticky="w")
        ttk.Entry(params, textvariable=self.phi_var, state="readonly").grid(row=0, column=7, sticky="ew", padx=(6, 0))

        ttk.Label(params, text="Public exponent e").grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(params, textvariable=self.e_var, state="readonly").grid(
            row=1, column=1, sticky="ew", padx=(6, 12), pady=(10, 0)
        )

        ttk.Label(params, text="Private exponent d").grid(row=1, column=2, sticky="w", pady=(10, 0))
        ttk.Entry(params, textvariable=self.d_var, state="readonly").grid(
            row=1, column=3, columnspan=5, sticky="ew", padx=(6, 0), pady=(10, 0)
        )

        buttons = ttk.Frame(params)
        buttons.grid(row=2, column=0, columnspan=8, sticky="ew", pady=(14, 0))
        for column in range(5):
            buttons.columnconfigure(column, weight=1)

        ttk.Button(buttons, text="Encrypt Plaintext", command=self.encrypt_current_plaintext).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(buttons, text="Save Ciphertext .txt", command=self.save_ciphertext_file).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(buttons, text="Load Ciphertext .txt", command=self.load_ciphertext_file).grid(
            row=0, column=2, sticky="ew", padx=6
        )
        ttk.Button(buttons, text="Decrypt Payload", command=self.decrypt_current_payload).grid(
            row=0, column=3, sticky="ew", padx=6
        )
        ttk.Button(buttons, text="Clear", command=self.clear_all).grid(
            row=0, column=4, sticky="ew", padx=(6, 0)
        )

        editors = ttk.Frame(self.root, padding=(12, 0, 12, 0))
        editors.grid(row=1, column=0, sticky="nsew")
        editors.columnconfigure(0, weight=1)
        editors.columnconfigure(1, weight=1)
        editors.rowconfigure(0, weight=1)
        editors.rowconfigure(1, weight=1)

        plaintext_frame = ttk.LabelFrame(editors, text="Plaintext Input", padding=10)
        plaintext_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
        plaintext_frame.rowconfigure(0, weight=1)
        plaintext_frame.columnconfigure(0, weight=1)

        self.plaintext_text = ScrolledText(plaintext_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.plaintext_text.grid(row=0, column=0, sticky="nsew")

        ciphertext_frame = ttk.LabelFrame(editors, text="Ciphertext Payload / File Content", padding=10)
        ciphertext_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        ciphertext_frame.rowconfigure(0, weight=1)
        ciphertext_frame.columnconfigure(0, weight=1)

        self.ciphertext_text = ScrolledText(ciphertext_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.ciphertext_text.grid(row=0, column=0, sticky="nsew")

        decrypted_frame = ttk.LabelFrame(editors, text="Decrypted Plaintext", padding=10)
        decrypted_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 0))
        decrypted_frame.rowconfigure(0, weight=1)
        decrypted_frame.columnconfigure(0, weight=1)

        self.decrypted_text = ScrolledText(decrypted_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.decrypted_text.grid(row=0, column=0, sticky="nsew")

        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(14, 6))
        status.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 10))

    def _get_text(self, widget: ScrolledText) -> str:
        return widget.get("1.0", "end-1c")

    def _set_text(self, widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)

    def _set_parameters(self, parameters: dict[str, int], *, include_primes: bool = True) -> None:
        if include_primes:
            self.p_var.set(str(parameters["p"]))
            self.q_var.set(str(parameters["q"]))
        self.n_var.set(str(parameters["n"]))
        self.phi_var.set(str(parameters["phi"]))
        self.e_var.set(str(parameters["e"]))
        self.d_var.set(str(parameters["d"]))

    def _set_public_key_only(self, n_value: int, e_value: int) -> None:
        self.p_var.set("")
        self.q_var.set("")
        self.n_var.set(str(n_value))
        self.e_var.set(str(e_value))
        self.phi_var.set("-")
        self.d_var.set("-")

    def _clear_parameters(self) -> None:
        self.p_var.set("")
        self.q_var.set("")
        self.n_var.set("-")
        self.phi_var.set("-")
        self.e_var.set("-")
        self.d_var.set("-")

    def encrypt_current_plaintext(self) -> None:
        plaintext = self._get_text(self.plaintext_text)

        try:
            p_value = int(self.p_var.get().strip())
            q_value = int(self.q_var.get().strip())
        except ValueError:
            messagebox.showerror(APP_TITLE, "p and q must be whole numbers.")
            return

        try:
            payload, parameters = encrypt_plaintext(plaintext, p_value, q_value)
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self._set_parameters(parameters)
        self._set_text(self.ciphertext_text, format_payload(payload))
        self._set_text(self.decrypted_text, "")
        self.status_var.set(
            "Encryption complete. The ciphertext payload includes the public key and is ready to save to a .txt file."
        )

    def save_ciphertext_file(self) -> None:
        payload_text = self._get_text(self.ciphertext_text)
        if not payload_text.strip():
            messagebox.showwarning(APP_TITLE, "There is no ciphertext payload to save yet.")
            return

        path = filedialog.asksaveasfilename(
            title="Save RSA ciphertext payload",
            defaultextension=".txt",
            filetypes=FILE_DIALOG_TYPES,
        )
        if not path:
            return

        file_path = Path(path)
        try:
            file_path.write_text(payload_text, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not save the file.\n\n{exc}")
            return

        self.status_var.set(f"Saved ciphertext payload to {file_path.name}.")

    def load_ciphertext_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Load RSA ciphertext payload",
            filetypes=FILE_DIALOG_TYPES,
        )
        if not path:
            return

        file_path = Path(path)
        try:
            payload_text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not read the file.\n\n{exc}")
            return

        self._set_text(self.ciphertext_text, payload_text)

        metadata = payload_metadata(payload_text)
        if metadata:
            self._set_public_key_only(metadata["n"], metadata["e"])
            self.status_var.set(
                f"Loaded {file_path.name}. Public key values were filled in; decrypting will recover p, q, Phi, and d."
            )
        else:
            self.status_var.set(f"Loaded {file_path.name}, but the payload format could not be recognized.")

    def decrypt_current_payload(self) -> None:
        payload_text = self._get_text(self.ciphertext_text)
        try:
            plaintext, parameters = decrypt_payload(payload_text)
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self._set_parameters(parameters)
        self._set_text(self.decrypted_text, plaintext)
        self.status_var.set(
            "Decryption complete. The app factored n, rebuilt Phi and the private key, and restored the plaintext."
        )

    def clear_all(self) -> None:
        self._clear_parameters()
        self._set_text(self.plaintext_text, "")
        self._set_text(self.ciphertext_text, "")
        self._set_text(self.decrypted_text, "")
        self.status_var.set("All fields were cleared.")


def main() -> None:
    root = tk.Tk()
    RsaApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
