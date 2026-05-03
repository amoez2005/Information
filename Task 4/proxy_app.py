from __future__ import annotations

import queue
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from shared import LOCAL_HOST, PROXY_PORT, VERIFIER_PORT, PacketReceiver, SignaturePacket, send_packet


APP_TITLE = "Task 4 - Application 2: Tampering Proxy"


class ProxyApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1160x800")
        self.root.minsize(960, 700)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.listen_host_var = tk.StringVar(value=LOCAL_HOST)
        self.listen_port_var = tk.StringVar(value=str(PROXY_PORT))
        self.forward_host_var = tk.StringVar(value=LOCAL_HOST)
        self.forward_port_var = tk.StringVar(value=str(VERIFIER_PORT))
        self.status_var = tk.StringVar(value="Start listening, receive a signed message, optionally tamper with the signature, then forward it.")

        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.receiver = PacketReceiver(self._handle_packet_from_thread, self._handle_error_from_thread)

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._process_queue)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        controls = ttk.LabelFrame(self.root, text="Proxy Controls", padding=14)
        controls.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        for column in range(8):
            controls.columnconfigure(column, weight=1)

        ttk.Label(controls, text="Listen host").grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.listen_host_var).grid(row=0, column=1, sticky="ew", padx=(6, 12))
        ttk.Label(controls, text="Listen port").grid(row=0, column=2, sticky="w")
        ttk.Entry(controls, textvariable=self.listen_port_var).grid(row=0, column=3, sticky="ew", padx=(6, 12))
        ttk.Label(controls, text="Verifier host").grid(row=0, column=4, sticky="w")
        ttk.Entry(controls, textvariable=self.forward_host_var).grid(row=0, column=5, sticky="ew", padx=(6, 12))
        ttk.Label(controls, text="Verifier port").grid(row=0, column=6, sticky="w")
        ttk.Entry(controls, textvariable=self.forward_port_var).grid(row=0, column=7, sticky="ew", padx=(6, 0))

        actions = ttk.Frame(controls)
        actions.grid(row=1, column=0, columnspan=8, sticky="ew", pady=(14, 0))
        for column in range(3):
            actions.columnconfigure(column, weight=1)

        ttk.Button(actions, text="Start Listening", command=self.start_listening).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(actions, text="Forward To Verifier", command=self.forward_packet).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(actions, text="Clear Fields", command=self.clear_fields).grid(
            row=0, column=2, sticky="ew", padx=(6, 0)
        )

        editors = ttk.Frame(self.root, padding=(12, 0, 12, 0))
        editors.grid(row=1, column=0, sticky="nsew")
        editors.columnconfigure(0, weight=1)
        editors.columnconfigure(1, weight=1)
        editors.rowconfigure(0, weight=1)
        editors.rowconfigure(1, weight=1)

        message_frame = ttk.LabelFrame(editors, text="Received Message", padding=10)
        message_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
        message_frame.columnconfigure(0, weight=1)
        message_frame.rowconfigure(0, weight=1)
        self.message_text = ScrolledText(message_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.message_text.grid(row=0, column=0, sticky="nsew")

        signature_frame = ttk.LabelFrame(editors, text="Signature (Editable For Tampering)", padding=10)
        signature_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        signature_frame.columnconfigure(0, weight=1)
        signature_frame.rowconfigure(0, weight=1)
        self.signature_text = ScrolledText(signature_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.signature_text.grid(row=0, column=0, sticky="nsew")

        key_frame = ttk.LabelFrame(editors, text="Public Key", padding=10)
        key_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))
        key_frame.columnconfigure(0, weight=1)
        key_frame.rowconfigure(0, weight=1)
        self.public_key_text = ScrolledText(key_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.public_key_text.grid(row=0, column=0, sticky="nsew")

        hash_frame = ttk.LabelFrame(editors, text="Original SHA-256 Hash From Signer", padding=10)
        hash_frame.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0))
        hash_frame.columnconfigure(0, weight=1)
        hash_frame.rowconfigure(0, weight=1)
        self.hash_text = ScrolledText(hash_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.hash_text.grid(row=0, column=0, sticky="nsew")

        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(14, 6))
        status.grid(row=2, column=0, sticky="ew", padx=12, pady=(8, 10))

    def _get_text(self, widget: ScrolledText) -> str:
        return widget.get("1.0", "end-1c")

    def _set_text(self, widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)

    def _handle_packet_from_thread(self, packet: SignaturePacket, address: tuple[str, int]) -> None:
        self._queue.put(("packet", (packet, address)))

    def _handle_error_from_thread(self, message: str) -> None:
        self._queue.put(("error", message))

    def _process_queue(self) -> None:
        while not self._queue.empty():
            kind, payload = self._queue.get()
            if kind == "packet":
                packet, address = payload
                self._set_text(self.message_text, packet.message)
                self._set_text(self.signature_text, packet.signature_b64)
                self._set_text(self.public_key_text, packet.public_key_pem)
                self._set_text(self.hash_text, packet.hash_hex)
                self.status_var.set(f"Received a signed message from {address[0]}:{address[1]}. You can now tamper with the signature or forward it unchanged.")
            else:
                self.status_var.set(str(payload))
        self.root.after(100, self._process_queue)

    def start_listening(self) -> None:
        try:
            self.receiver.start(self.listen_host_var.get().strip(), int(self.listen_port_var.get().strip()))
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.status_var.set("Application 2 is listening for Application 1 on the configured socket.")

    def forward_packet(self) -> None:
        try:
            packet = SignaturePacket(
                message=self._get_text(self.message_text),
                signature_b64=self._get_text(self.signature_text),
                public_key_pem=self._get_text(self.public_key_text),
                hash_hex=self._get_text(self.hash_text),
            )
            send_packet(packet, self.forward_host_var.get().strip(), int(self.forward_port_var.get().strip()))
        except (ValueError, OSError) as exc:
            messagebox.showerror(APP_TITLE, f"Could not forward the packet to Application 3.\n\n{exc}")
            return

        self.status_var.set("Forwarded the current packet to Application 3. If you changed the signature, verification should fail there.")

    def clear_fields(self) -> None:
        self._set_text(self.message_text, "")
        self._set_text(self.signature_text, "")
        self._set_text(self.public_key_text, "")
        self._set_text(self.hash_text, "")
        self.status_var.set("Cleared the proxy fields.")

    def _on_close(self) -> None:
        self.receiver.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    ProxyApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
