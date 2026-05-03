from __future__ import annotations

import queue
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from shared import CRYPTO_IMPORT_ERROR, LOCAL_HOST, PacketReceiver, SignaturePacket, VERIFIER_PORT, show_missing_dependency_error, verify_packet


APP_TITLE = "Task 4 - Application 3: Signature Verifier"


class VerifierApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1160x840")
        self.root.minsize(980, 720)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.listen_host_var = tk.StringVar(value=LOCAL_HOST)
        self.listen_port_var = tk.StringVar(value=str(VERIFIER_PORT))
        self.result_var = tk.StringVar(value="Waiting for a signed message.")
        self.status_var = tk.StringVar(value="Start listening, then receive data from Application 2 to verify the signature.")

        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.receiver = PacketReceiver(self._handle_packet_from_thread, self._handle_error_from_thread)

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._process_queue)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        controls = ttk.LabelFrame(self.root, text="Verifier Controls", padding=14)
        controls.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        for column in range(5):
            controls.columnconfigure(column, weight=1)

        ttk.Label(controls, text="Listen host").grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, textvariable=self.listen_host_var).grid(row=0, column=1, sticky="ew", padx=(6, 12))
        ttk.Label(controls, text="Listen port").grid(row=0, column=2, sticky="w")
        ttk.Entry(controls, textvariable=self.listen_port_var).grid(row=0, column=3, sticky="ew", padx=(6, 12))
        ttk.Button(controls, text="Start Listening", command=self.start_listening).grid(row=0, column=4, sticky="ew")

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

        signature_frame = ttk.LabelFrame(editors, text="Received Signature", padding=10)
        signature_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        signature_frame.columnconfigure(0, weight=1)
        signature_frame.rowconfigure(0, weight=1)
        self.signature_text = ScrolledText(signature_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.signature_text.grid(row=0, column=0, sticky="nsew")

        key_frame = ttk.LabelFrame(editors, text="Received Public Key", padding=10)
        key_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))
        key_frame.columnconfigure(0, weight=1)
        key_frame.rowconfigure(0, weight=1)
        self.public_key_text = ScrolledText(key_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.public_key_text.grid(row=0, column=0, sticky="nsew")

        result_frame = ttk.LabelFrame(editors, text="Verification Result", padding=10)
        result_frame.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(1, weight=1)

        ttk.Label(result_frame, textvariable=self.result_var, font=("Segoe UI", 14, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )
        self.details_text = ScrolledText(result_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.details_text.grid(row=1, column=0, sticky="nsew")

        action_row = ttk.Frame(self.root, padding=(12, 8, 12, 0))
        action_row.grid(row=2, column=0, sticky="ew")
        action_row.columnconfigure(0, weight=1)
        action_row.columnconfigure(1, weight=1)

        ttk.Button(action_row, text="Verify Current Payload Again", command=self.verify_current_payload).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(action_row, text="Clear Fields", command=self.clear_fields).grid(
            row=0, column=1, sticky="ew", padx=(6, 0)
        )

        status = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(14, 6))
        status.grid(row=3, column=0, sticky="ew", padx=12, pady=(8, 10))

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
                self.status_var.set(f"Received a payload from {address[0]}:{address[1]}. Verifying the signature now.")
                self._apply_verification(packet)
            else:
                self.status_var.set(str(payload))
        self.root.after(100, self._process_queue)

    def start_listening(self) -> None:
        try:
            self.receiver.start(self.listen_host_var.get().strip(), int(self.listen_port_var.get().strip()))
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.status_var.set("Application 3 is listening for Application 2 on the configured socket.")

    def _current_packet(self) -> SignaturePacket | None:
        try:
            return SignaturePacket(
                message=self._get_text(self.message_text),
                signature_b64=self._get_text(self.signature_text),
                public_key_pem=self._get_text(self.public_key_text),
                hash_hex="manual-check",
            )
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return None

    def verify_current_payload(self) -> None:
        packet = self._current_packet()
        if packet is None:
            return
        self._apply_verification(packet)

    def _apply_verification(self, packet: SignaturePacket) -> None:
        result = verify_packet(packet)
        if result.is_valid:
            self.result_var.set("VALID SIGNATURE")
        else:
            self.result_var.set("INVALID OR TAMPERED SIGNATURE")

        details = (
            f"Computed SHA-256 hash:\n{result.computed_hash_hex}\n\n"
            f"Received signer hash:\n{packet.hash_hex}\n\n"
            f"Verification details:\n{result.details}"
        )
        self._set_text(self.details_text, details)
        self.status_var.set("Verification completed.")

    def clear_fields(self) -> None:
        self._set_text(self.message_text, "")
        self._set_text(self.signature_text, "")
        self._set_text(self.public_key_text, "")
        self._set_text(self.details_text, "")
        self.result_var.set("Waiting for a signed message.")
        self.status_var.set("Cleared the verifier fields.")

    def _on_close(self) -> None:
        self.receiver.stop()
        self.root.destroy()


def main() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        show_missing_dependency_error(APP_TITLE)
        return

    root = tk.Tk()
    VerifierApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
