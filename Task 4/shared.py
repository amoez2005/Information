from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import socket
import sys
import threading
from typing import Callable
import tkinter as tk
from tkinter import messagebox

CRYPTO_IMPORT_ERROR = None

try:
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
    SHA256 = None
    RSA = None
    pkcs1_15 = None
    CRYPTO_IMPORT_ERROR = exc


LOCAL_HOST = "127.0.0.1"
PROXY_PORT = 5101
VERIFIER_PORT = 5102
BUFFER_SIZE = 65536


def ensure_crypto_available() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise RuntimeError("PyCryptodome is required to use the RSA signature applications.")


def show_missing_dependency_error(app_title: str) -> None:
    root = tk.Tk()
    root.withdraw()
    interpreter = sys.executable
    messagebox.showerror(
        app_title,
        "PyCryptodome is required to run this application.\n\n"
        f"Current interpreter:\n{interpreter}\n\n"
        "Install it for this interpreter with:\n"
        f"\"{interpreter}\" -m pip install -r requirements.txt",
    )
    root.destroy()


@dataclass
class SignaturePacket:
    message: str
    signature_b64: str
    public_key_pem: str
    hash_hex: str
    algorithm: str = "RSA-PKCS1-v1_5"
    hash_algorithm: str = "SHA-256"

    def to_dict(self) -> dict[str, str]:
        return {
            "message": self.message,
            "signature_b64": self.signature_b64,
            "public_key_pem": self.public_key_pem,
            "hash_hex": self.hash_hex,
            "algorithm": self.algorithm,
            "hash_algorithm": self.hash_algorithm,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "SignaturePacket":
        message = data.get("message")
        signature_b64 = data.get("signature_b64")
        public_key_pem = data.get("public_key_pem")
        hash_hex = data.get("hash_hex")
        algorithm = data.get("algorithm", "RSA-PKCS1-v1_5")
        hash_algorithm = data.get("hash_algorithm", "SHA-256")

        if not isinstance(message, str) or not message:
            raise ValueError("Payload must contain a non-empty message.")
        if not isinstance(signature_b64, str) or not signature_b64:
            raise ValueError("Payload must contain a non-empty base64 signature.")
        if not isinstance(public_key_pem, str) or not public_key_pem:
            raise ValueError("Payload must contain a public key.")
        if not isinstance(hash_hex, str) or not hash_hex:
            raise ValueError("Payload must contain a message hash.")
        if not isinstance(algorithm, str) or not isinstance(hash_algorithm, str):
            raise ValueError("Payload algorithm fields must be text.")

        return cls(
            message=message,
            signature_b64=signature_b64,
            public_key_pem=public_key_pem,
            hash_hex=hash_hex,
            algorithm=algorithm,
            hash_algorithm=hash_algorithm,
        )

    @classmethod
    def from_json(cls, raw_text: str) -> "SignaturePacket":
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError("Received data is not valid JSON.") from exc

        if not isinstance(data, dict):
            raise ValueError("Received JSON payload must be an object.")
        return cls.from_dict(data)


@dataclass
class VerificationResult:
    is_valid: bool
    computed_hash_hex: str
    details: str


def generate_rsa_keypair(bits: int = 2048) -> tuple[str, str]:
    ensure_crypto_available()
    if bits not in {1024, 2048, 3072}:
        raise ValueError("Key size must be 1024, 2048, or 3072 bits.")

    key = RSA.generate(bits)
    private_key_pem = key.export_key().decode("utf-8")
    public_key_pem = key.publickey().export_key().decode("utf-8")
    return private_key_pem, public_key_pem


def sign_message(message: str, private_key_pem: str, public_key_pem: str) -> SignaturePacket:
    ensure_crypto_available()
    if not message:
        raise ValueError("Message cannot be empty.")
    if not private_key_pem.strip():
        raise ValueError("Private key is missing.")
    if not public_key_pem.strip():
        raise ValueError("Public key is missing.")

    private_key = RSA.import_key(private_key_pem)
    digest = SHA256.new(message.encode("utf-8"))
    signature = pkcs1_15.new(private_key).sign(digest)

    return SignaturePacket(
        message=message,
        signature_b64=base64.b64encode(signature).decode("utf-8"),
        public_key_pem=public_key_pem,
        hash_hex=digest.hexdigest(),
    )


def verify_packet(packet: SignaturePacket) -> VerificationResult:
    ensure_crypto_available()

    digest = SHA256.new(packet.message.encode("utf-8"))
    try:
        signature = base64.b64decode(packet.signature_b64, validate=True)
    except Exception:
        return VerificationResult(
            is_valid=False,
            computed_hash_hex=digest.hexdigest(),
            details="The signature is not valid base64, so verification failed immediately.",
        )

    try:
        public_key = RSA.import_key(packet.public_key_pem)
        pkcs1_15.new(public_key).verify(digest, signature)
    except (ValueError, TypeError):
        return VerificationResult(
            is_valid=False,
            computed_hash_hex=digest.hexdigest(),
            details="The decrypted signature does not match the SHA-256 hash of the received message.",
        )

    return VerificationResult(
        is_valid=True,
        computed_hash_hex=digest.hexdigest(),
        details="The signature matches the SHA-256 hash of the received message.",
    )


def send_packet(packet: SignaturePacket, host: str, port: int) -> None:
    if not host.strip():
        raise ValueError("Host cannot be empty.")
    if port <= 0 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    payload = packet.to_json().encode("utf-8")
    with socket.create_connection((host, port), timeout=5) as client:
        client.sendall(payload)


class PacketReceiver:
    def __init__(
        self,
        on_packet: Callable[[SignaturePacket, tuple[str, int]], None],
        on_error: Callable[[str], None],
    ) -> None:
        self.on_packet = on_packet
        self.on_error = on_error
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._host = LOCAL_HOST
        self._port = 0

    def start(self, host: str, port: int) -> None:
        if not host.strip():
            raise ValueError("Host cannot be empty.")
        if port <= 0 or port > 65535:
            raise ValueError("Port must be between 1 and 65535.")

        self.stop()
        self._host = host
        self._port = port
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            try:
                with socket.create_connection((self._host, self._port), timeout=1):
                    pass
            except OSError:
                pass
            self._thread.join(timeout=1)

    def _serve(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self._host, self._port))
                server.listen()
                server.settimeout(0.5)

                while not self._stop_event.is_set():
                    try:
                        connection, address = server.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

                    with connection:
                        raw_bytes = bytearray()
                        while True:
                            chunk = connection.recv(BUFFER_SIZE)
                            if not chunk:
                                break
                            raw_bytes.extend(chunk)

                    if not raw_bytes:
                        continue

                    try:
                        packet = SignaturePacket.from_json(raw_bytes.decode("utf-8"))
                    except ValueError as exc:
                        self.on_error(str(exc))
                        continue

                    self.on_packet(packet, address)
        except OSError as exc:
            if not self._stop_event.is_set():
                self.on_error(f"Socket server error: {exc}")
