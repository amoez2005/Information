from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from shared import LOCAL_HOST, PROXY_PORT, generate_rsa_keypair, send_packet, show_missing_dependency_error, sign_message


APP_TITLE = "Task 4 - Application 1: RSA Signer"


class SignerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1100x760")
        self.root.minsize(920, 680)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.key_size_var = tk.StringVar(value="2048")
        self.target_host_var = tk.StringVar(value=LOCAL_HOST)
        self.target_port_var = tk.StringVar(value=str(PROXY_PORT))
        self.status_var = tk.StringVar(value="Generate a key pair, enter a message, and sign/send it to Application 2.")

        self.private_key_pem = ""
        self.public_key_pem = ""

        self._build_ui()
        self.generate_key_pair()

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        controls = ttk.LabelFrame(self.root, text="Signer Controls", padding=14)
        controls.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        for column in range(6):
            controls.columnconfigure(column, weight=1)

        ttk.Label(controls, text="Key size").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            controls,
            textvariable=self.key_size_var,
            values=("1024", "2048", "3072"),
            state="readonly",
            width=10,
        ).grid(row=0, column=1, sticky="w", padx=(6, 12))

        ttk.Label(controls, text="Proxy host").grid(row=0, column=2, sticky="w")
        ttk.Entry(controls, textvariable=self.target_host_var).grid(row=0, column=3, sticky="ew", padx=(6, 12))

        ttk.Label(controls, text="Proxy port").grid(row=0, column=4, sticky="w")
        ttk.Entry(controls, textvariable=self.target_port_var).grid(row=0, column=5, sticky="ew", padx=(6, 0))

        actions = ttk.Frame(controls)
        actions.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(14, 0))
        for column in range(3):
            actions.columnconfigure(column, weight=1)

        ttk.Button(actions, text="Generate New Key Pair", command=self.generate_key_pair).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(actions, text="Sign Message", command=self.sign_only).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(actions, text="Sign And Send To Proxy", command=self.sign_and_send).grid(
            row=0, column=2, sticky="ew", padx=(6, 0)
        )

        editors = ttk.Frame(self.root, padding=(12, 0, 12, 0))
        editors.grid(row=1, column=0, sticky="nsew")
        editors.columnconfigure(0, weight=1)
        editors.columnconfigure(1, weight=1)
        editors.rowconfigure(0, weight=1)
        editors.rowconfigure(1, weight=1)

        message_frame = ttk.LabelFrame(editors, text="Message To Sign", padding=10)
        message_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
        message_frame.columnconfigure(0, weight=1)
        message_frame.rowconfigure(0, weight=1)
        self.message_text = ScrolledText(message_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.message_text.grid(row=0, column=0, sticky="nsew")

        signature_frame = ttk.LabelFrame(editors, text="Generated Signature (Base64)", padding=10)
        signature_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        signature_frame.columnconfigure(0, weight=1)
        signature_frame.rowconfigure(0, weight=1)
        self.signature_text = ScrolledText(signature_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.signature_text.grid(row=0, column=0, sticky="nsew")

        public_key_frame = ttk.LabelFrame(editors, text="Public Key", padding=10)
        public_key_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))
        public_key_frame.columnconfigure(0, weight=1)
        public_key_frame.rowconfigure(0, weight=1)
        self.public_key_text = ScrolledText(public_key_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.public_key_text.grid(row=0, column=0, sticky="nsew")

        hash_frame = ttk.LabelFrame(editors, text="SHA-256 Hash", padding=10)
        hash_frame.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0))
        hash_frame.columnconfigure(0, weight=1)
        hash_frame.rowconfigure(0, weight=1)
        self.hash_text = ScrolledText(hash_frame, wrap=tk.WORD, font=("Consolas", 10), height=8)
        self.hash_text.grid(row=0, column=0, sticky="nsew")

        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(14, 6))
        status.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 10))

    def _get_text(self, widget: ScrolledText) -> str:
        return widget.get("1.0", "end-1c")

    def _set_text(self, widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)

    def generate_key_pair(self) -> None:
        try:
            private_key_pem, public_key_pem = generate_rsa_keypair(int(self.key_size_var.get()))
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.private_key_pem = private_key_pem
        self.public_key_pem = public_key_pem
        self._set_text(self.public_key_text, public_key_pem)
        self.status_var.set(f"Generated a new RSA-{self.key_size_var.get()} key pair for signing.")

    def _sign_current_message(self):
        message = self._get_text(self.message_text)
        try:
            packet = sign_message(message, self.private_key_pem, self.public_key_pem)
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return None

        self._set_text(self.signature_text, packet.signature_b64)
        self._set_text(self.hash_text, packet.hash_hex)
        return packet

    def sign_only(self) -> None:
        packet = self._sign_current_message()
        if packet is None:
            return
        self.status_var.set("Message signed successfully. You can now send it to Application 2.")

    def sign_and_send(self) -> None:
        packet = self._sign_current_message()
        if packet is None:
            return

        try:
            send_packet(packet, self.target_host_var.get().strip(), int(self.target_port_var.get().strip()))
        except (ValueError, OSError) as exc:
            messagebox.showerror(APP_TITLE, f"Could not send the packet to Application 2.\n\n{exc}")
            return

        self.status_var.set("Signed message sent to Application 2 over a socket connection.")


def main() -> None:
    from shared import CRYPTO_IMPORT_ERROR

    if CRYPTO_IMPORT_ERROR is not None:
        show_missing_dependency_error(APP_TITLE)
        return

    root = tk.Tk()
    SignerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
