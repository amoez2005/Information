#!/usr/bin/env python3

from __future__ import annotations

import base64
import csv
import hmac
import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
import re
import secrets
import string
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

CRYPTO_IMPORT_ERROR = None

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
    AES = None
    get_random_bytes = None
    CRYPTO_IMPORT_ERROR = exc


APP_TITLE = "Task 5 - Password Manager"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
VAULTS_DIR = DATA_DIR / "vaults"
USERS_FILE = DATA_DIR / "users.txt"
CSV_COLUMNS = ["Title", "EncryptedPassword", "URL", "Notes"]
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
AES_NONCE_SIZE = 16
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"


@dataclass
class UserSession:
    user_key: str
    display_name: str
    vault_key: bytes
    plain_path: Path
    encrypted_path: Path
    entries: list[dict[str, str]]


def ensure_crypto_available() -> None:
    if CRYPTO_IMPORT_ERROR is not None:
        raise RuntimeError("PyCryptodome is required to run Task 5.")


def show_missing_dependency_error() -> None:
    root = tk.Tk()
    root.withdraw()
    interpreter = sys.executable
    messagebox.showerror(
        APP_TITLE,
        "PyCryptodome is required to run this application.\n\n"
        f"Current interpreter:\n{interpreter}\n\n"
        "Install it for this interpreter with:\n"
        f"\"{interpreter}\" -m pip install -r requirements.txt",
    )
    root.destroy()


def bootstrap_storage() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    VAULTS_DIR.mkdir(exist_ok=True)
    if not USERS_FILE.exists():
        USERS_FILE.write_text("{}", encoding="utf-8")


def load_user_registry() -> dict[str, dict[str, str]]:
    bootstrap_storage()
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("The users.txt file is corrupted and cannot be read.") from exc

    if not isinstance(data, dict):
        raise ValueError("The users.txt file has an invalid structure.")
    return data


def save_user_registry(registry: dict[str, dict[str, str]]) -> None:
    USERS_FILE.write_text(json.dumps(registry, indent=2), encoding="utf-8")


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_username(username: str) -> str:
    cleaned = username.strip()
    if not cleaned:
        raise ValueError("Username cannot be empty.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", cleaned):
        raise ValueError("Username must be 3-32 characters and use letters, digits, '.', '_' or '-'.")
    return cleaned


def validate_login_password(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")


def pbkdf2_bytes(secret: str, salt: bytes, length: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=length,
    )


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(AES_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def decrypt_bytes(payload: bytes, key: bytes) -> bytes:
    if len(payload) < AES_NONCE_SIZE + 16:
        raise ValueError("Encrypted data is too short.")

    nonce = payload[:AES_NONCE_SIZE]
    tag = payload[AES_NONCE_SIZE:AES_NONCE_SIZE + 16]
    ciphertext = payload[AES_NONCE_SIZE + 16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError("Decryption failed. The password may be incorrect or the file may be corrupted.") from exc


def encrypt_text_value(value: str, key: bytes) -> str:
    token = encrypt_bytes(value.encode("utf-8"), key)
    return base64.b64encode(token).decode("utf-8")


def decrypt_text_value(token_text: str, key: bytes) -> str:
    try:
        token = base64.b64decode(token_text)
    except Exception as exc:
        raise ValueError("Stored password data is not valid Base64.") from exc
    return decrypt_bytes(token, key).decode("utf-8")


def shorten_for_table(value: str, length: int = 50) -> str:
    cleaned = " ".join(value.splitlines()).strip()
    if len(cleaned) <= length:
        return cleaned
    return cleaned[: length - 3] + "..."


def write_empty_vault(path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()


def read_entries_from_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        write_empty_vault(path)

    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        entries: list[dict[str, str]] = []
        for row in reader:
            entries.append(
                {
                    "Title": row.get("Title", ""),
                    "EncryptedPassword": row.get("EncryptedPassword", ""),
                    "URL": row.get("URL", ""),
                    "Notes": row.get("Notes", ""),
                }
            )
    return entries


def write_entries_to_csv(path: Path, entries: list[dict[str, str]]) -> None:
    ordered_entries = sorted(entries, key=lambda item: item["Title"].lower())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(ordered_entries)


def register_user(username: str, password: str) -> None:
    ensure_crypto_available()
    cleaned_username = validate_username(username)
    validate_login_password(password)

    registry = load_user_registry()
    user_key = normalize_username(cleaned_username)
    if user_key in registry:
        raise ValueError("That username already exists.")

    auth_salt = get_random_bytes(SALT_SIZE)
    vault_salt = get_random_bytes(SALT_SIZE)
    auth_hash = pbkdf2_bytes(password, auth_salt, 32)
    vault_key = pbkdf2_bytes(password, vault_salt, 32)

    filename_stem = re.sub(r"[^a-z0-9_.-]", "_", user_key)
    plain_path = VAULTS_DIR / f"{filename_stem}.csv"
    encrypted_path = VAULTS_DIR / f"{filename_stem}.csv.enc"

    write_empty_vault(plain_path)
    encrypted_path.write_bytes(encrypt_bytes(plain_path.read_bytes(), vault_key))
    plain_path.unlink(missing_ok=True)

    registry[user_key] = {
        "display_name": cleaned_username,
        "auth_salt": base64.b64encode(auth_salt).decode("utf-8"),
        "auth_hash": base64.b64encode(auth_hash).decode("utf-8"),
        "vault_salt": base64.b64encode(vault_salt).decode("utf-8"),
        "vault_file": encrypted_path.name,
    }
    save_user_registry(registry)


def login_user(username: str, password: str) -> UserSession:
    ensure_crypto_available()
    cleaned_username = validate_username(username)
    validate_login_password(password)

    registry = load_user_registry()
    user_key = normalize_username(cleaned_username)
    record = registry.get(user_key)
    if record is None:
        raise ValueError("That user does not exist.")

    auth_salt = base64.b64decode(record["auth_salt"])
    expected_hash = base64.b64decode(record["auth_hash"])
    actual_hash = pbkdf2_bytes(password, auth_salt, len(expected_hash))

    if not hmac.compare_digest(actual_hash, expected_hash):
        raise ValueError("Incorrect username or password.")

    vault_salt = base64.b64decode(record["vault_salt"])
    vault_key = pbkdf2_bytes(password, vault_salt, 32)

    encrypted_path = VAULTS_DIR / record["vault_file"]
    plain_path = encrypted_path.with_suffix("")

    if plain_path.exists():
        pass
    elif encrypted_path.exists():
        plaintext = decrypt_bytes(encrypted_path.read_bytes(), vault_key)
        plain_path.write_bytes(plaintext)
    else:
        write_empty_vault(plain_path)

    entries = read_entries_from_csv(plain_path)
    return UserSession(
        user_key=user_key,
        display_name=record.get("display_name", cleaned_username),
        vault_key=vault_key,
        plain_path=plain_path,
        encrypted_path=encrypted_path,
        entries=entries,
    )


def lock_session(session: UserSession) -> None:
    ensure_crypto_available()
    write_entries_to_csv(session.plain_path, session.entries)
    plaintext = session.plain_path.read_bytes()
    session.encrypted_path.write_bytes(encrypt_bytes(plaintext, session.vault_key))
    session.plain_path.unlink(missing_ok=True)


class PasswordManagerApp:
    def __init__(self, root: tk.Tk) -> None:
        bootstrap_storage()

        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1280x860")
        self.root.minsize(1100, 760)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.session: UserSession | None = None
        self.selected_entry_title: str | None = None

        self.auth_username_var = tk.StringVar()
        self.auth_password_var = tk.StringVar()
        self.auth_confirm_var = tk.StringVar()
        self.auth_heading_var = tk.StringVar()
        self.auth_subtitle_var = tk.StringVar()
        self.auth_primary_var = tk.StringVar()
        self.auth_secondary_var = tk.StringVar()
        self.search_var = tk.StringVar()
        self.entry_title_var = tk.StringVar()
        self.entry_url_var = tk.StringVar()
        self.entry_password_var = tk.StringVar()
        self.generator_length_var = tk.StringVar(value="18")
        self.revealed_password_var = tk.StringVar()
        self.auth_mode = "login"
        self.status_var = tk.StringVar(
            value="Log in to open your encrypted password vault."
        )

        self._build_ui()
        self._show_auth_view()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.container = ttk.Frame(self.root, padding=14)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.container.columnconfigure(0, weight=1)
        self.container.rowconfigure(0, weight=1)

        self.auth_frame = ttk.Frame(self.container)
        self.auth_frame.grid(row=0, column=0, sticky="nsew")
        self.auth_frame.columnconfigure(0, weight=1)
        self.auth_frame.rowconfigure(0, weight=1)

        self.vault_frame = ttk.Frame(self.container)
        self.vault_frame.grid(row=0, column=0, sticky="nsew")
        self.vault_frame.columnconfigure(0, weight=1)
        self.vault_frame.rowconfigure(1, weight=1)

        self._build_auth_view()
        self._build_vault_view()

        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=(14, 6))
        self.status_bar.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))

    def _build_auth_view(self) -> None:
        card = ttk.LabelFrame(self.auth_frame, text="User Access", padding=22)
        card.place(relx=0.5, rely=0.5, anchor="center")
        for column in range(2):
            card.columnconfigure(column, weight=1)

        ttk.Label(card, text="Password Manager", font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        ttk.Label(card, textvariable=self.auth_heading_var, font=("Segoe UI", 12, "bold")).grid(
            row=1, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(card, textvariable=self.auth_subtitle_var, wraplength=420).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 14)
        )

        ttk.Label(card, text="Username").grid(row=3, column=0, sticky="w")
        ttk.Entry(card, textvariable=self.auth_username_var, width=34).grid(
            row=3, column=1, sticky="ew", padx=(10, 0), pady=(0, 8)
        )

        ttk.Label(card, text="Password").grid(row=4, column=0, sticky="w")
        ttk.Entry(card, textvariable=self.auth_password_var, show="*", width=34).grid(
            row=4, column=1, sticky="ew", padx=(10, 0), pady=(0, 8)
        )

        self.confirm_label = ttk.Label(card, text="Confirm password")
        self.confirm_label.grid(row=5, column=0, sticky="w")
        self.confirm_entry = ttk.Entry(card, textvariable=self.auth_confirm_var, show="*", width=34)
        self.confirm_entry.grid(row=5, column=1, sticky="ew", padx=(10, 0), pady=(0, 16))

        buttons = ttk.Frame(card)
        buttons.grid(row=6, column=0, columnspan=2, sticky="ew")
        buttons.columnconfigure(0, weight=1)
        buttons.columnconfigure(1, weight=1)

        self.auth_primary_button = ttk.Button(buttons, textvariable=self.auth_primary_var, command=self._submit_auth)
        self.auth_primary_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.auth_secondary_button = ttk.Button(buttons, textvariable=self.auth_secondary_var, command=self._toggle_auth_mode)
        self.auth_secondary_button.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self._apply_auth_mode()

    def _build_vault_view(self) -> None:
        header = ttk.Frame(self.vault_frame)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)

        self.welcome_label = ttk.Label(header, text="", font=("Segoe UI", 16, "bold"))
        self.welcome_label.grid(row=0, column=0, sticky="w")
        ttk.Button(header, text="Log Out", command=self._logout).grid(row=0, column=1, sticky="e")

        body = ttk.Frame(self.vault_frame)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ttk.LabelFrame(body, text="Stored Entries", padding=12)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        search_row = ttk.Frame(left)
        search_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        search_row.columnconfigure(1, weight=1)

        ttk.Label(search_row, text="Search by title").grid(row=0, column=0, sticky="w")
        search_entry = ttk.Entry(search_row, textvariable=self.search_var)
        search_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        search_entry.bind("<KeyRelease>", lambda _event: self._refresh_tree())
        ttk.Button(search_row, text="Search", command=self._refresh_tree).grid(row=0, column=2, padx=(0, 6))
        ttk.Button(search_row, text="Clear Search", command=self._clear_search).grid(row=0, column=3)

        tree_frame = ttk.Frame(left)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("Title", "URL", "Notes"),
            show="headings",
            selectmode="browse",
        )
        for column, width in (("Title", 180), ("URL", 220), ("Notes", 280)):
            self.tree.heading(column, text=column)
            self.tree.column(column, width=width, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        right = ttk.LabelFrame(body, text="Entry Editor", padding=12)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.columnconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)

        ttk.Label(right, text="Title").grid(row=0, column=0, sticky="w")
        ttk.Entry(right, textvariable=self.entry_title_var).grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=(0, 8))

        ttk.Label(right, text="URL / Application").grid(row=1, column=0, sticky="w")
        ttk.Entry(right, textvariable=self.entry_url_var).grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(0, 8))

        ttk.Label(right, text="Password").grid(row=2, column=0, sticky="w")
        password_row = ttk.Frame(right)
        password_row.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=(0, 8))
        password_row.columnconfigure(0, weight=1)
        password_row.columnconfigure(3, weight=0)
        ttk.Entry(password_row, textvariable=self.entry_password_var, show="*").grid(row=0, column=0, sticky="ew")
        ttk.Label(password_row, text="Length").grid(row=0, column=1, padx=(10, 6))
        ttk.Spinbox(password_row, from_=8, to=64, textvariable=self.generator_length_var, width=6).grid(row=0, column=2)
        ttk.Button(password_row, text="Generate", command=self._generate_password).grid(row=0, column=3, padx=(10, 0))

        ttk.Label(right, text="Notes").grid(row=3, column=0, sticky="nw")
        self.notes_text = ScrolledText(right, wrap=tk.WORD, font=("Consolas", 10), height=10)
        self.notes_text.grid(row=3, column=1, sticky="nsew", padx=(10, 0), pady=(0, 8))

        reveal_frame = ttk.LabelFrame(right, text="Stored Password Reveal", padding=10)
        reveal_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 8))
        reveal_frame.columnconfigure(0, weight=1)
        reveal_frame.columnconfigure(1, weight=0)
        reveal_frame.columnconfigure(2, weight=0)
        reveal_frame.columnconfigure(3, weight=0)

        ttk.Entry(reveal_frame, textvariable=self.revealed_password_var, state="readonly").grid(
            row=0, column=0, sticky="ew"
        )
        ttk.Button(reveal_frame, text="Reveal", command=self._reveal_selected_password).grid(row=0, column=1, padx=(8, 6))
        ttk.Button(reveal_frame, text="Hide", command=self._hide_revealed_password).grid(row=0, column=2, padx=6)
        ttk.Button(reveal_frame, text="Copy", command=self._copy_revealed_password).grid(row=0, column=3, padx=(6, 0))

        action_row = ttk.Frame(right)
        action_row.grid(row=5, column=0, columnspan=2, sticky="ew")
        for column in range(4):
            action_row.columnconfigure(column, weight=1)

        ttk.Button(action_row, text="Add New Entry", command=self._add_entry).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(action_row, text="Update Selected", command=self._update_entry).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(action_row, text="Delete Selected", command=self._delete_entry).grid(row=0, column=2, sticky="ew", padx=6)
        ttk.Button(action_row, text="Clear Form", command=self._clear_entry_form).grid(row=0, column=3, sticky="ew", padx=(6, 0))

    def _show_auth_view(self) -> None:
        self.auth_mode = "login"
        self._apply_auth_mode()
        self.vault_frame.grid_remove()
        self.auth_frame.grid()

    def _show_vault_view(self) -> None:
        self.auth_frame.grid_remove()
        self.vault_frame.grid()

    def _get_notes_text(self) -> str:
        return self.notes_text.get("1.0", "end-1c")

    def _set_notes_text(self, value: str) -> None:
        self.notes_text.delete("1.0", tk.END)
        self.notes_text.insert("1.0", value)

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    def _clear_auth_fields(self) -> None:
        self.auth_password_var.set("")
        self.auth_confirm_var.set("")

    def _apply_auth_mode(self) -> None:
        if self.auth_mode == "login":
            self.auth_heading_var.set("Log In")
            self.auth_subtitle_var.set("Enter your username and password to decrypt and open your password vault.")
            self.auth_primary_var.set("Log In")
            self.auth_secondary_var.set("Register")
            self.confirm_label.grid_remove()
            self.confirm_entry.grid_remove()
        else:
            self.auth_heading_var.set("Register New User")
            self.auth_subtitle_var.set("Create an account first. After registration, your personal encrypted vault will be created automatically.")
            self.auth_primary_var.set("Create Account")
            self.auth_secondary_var.set("Back To Login")
            self.confirm_label.grid()
            self.confirm_entry.grid()

    def _toggle_auth_mode(self) -> None:
        self.auth_confirm_var.set("")
        if self.auth_mode == "login":
            self.auth_mode = "register"
            self._apply_auth_mode()
            self._set_status("Registration mode opened. Create a new user account first.")
        else:
            self.auth_mode = "login"
            self._apply_auth_mode()
            self._set_status("Login mode opened. Enter your credentials to unlock the vault.")

    def _submit_auth(self) -> None:
        if self.auth_mode == "login":
            self._login()
        else:
            self._register()

    def _selected_entry(self) -> dict[str, str] | None:
        if self.session is None or self.selected_entry_title is None:
            return None

        target = self.selected_entry_title.lower()
        for entry in self.session.entries:
            if entry["Title"].lower() == target:
                return entry
        return None

    def _find_entry_index_by_title(self, title: str) -> int | None:
        if self.session is None:
            return None
        target = title.strip().lower()
        for index, entry in enumerate(self.session.entries):
            if entry["Title"].strip().lower() == target:
                return index
        return None

    def _persist_entries(self) -> None:
        if self.session is None:
            return
        write_entries_to_csv(self.session.plain_path, self.session.entries)

    def _register(self) -> None:
        username = self.auth_username_var.get()
        password = self.auth_password_var.get()
        confirm = self.auth_confirm_var.get()

        if password != confirm:
            messagebox.showerror(APP_TITLE, "Password and confirmation do not match.")
            return

        try:
            register_user(username, password)
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.auth_mode = "login"
        self._apply_auth_mode()
        self._set_status("User registered successfully. Logging in to the new encrypted vault now.")
        self._login()

    def _login(self) -> None:
        username = self.auth_username_var.get()
        password = self.auth_password_var.get()

        try:
            self.session = login_user(username, password)
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.welcome_label.configure(text=f"Logged in as {self.session.display_name}")
        self._refresh_tree()
        self._clear_entry_form()
        self._clear_auth_fields()
        self._show_vault_view()
        self._set_status("Vault decrypted and loaded. Search, add, update, or delete entries as needed.")

    def _logout(self) -> None:
        if self.session is None:
            self._show_auth_view()
            return

        try:
            lock_session(self.session)
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_TITLE, f"Could not encrypt the vault on logout.\n\n{exc}")
            return

        display_name = self.session.display_name
        self.session = None
        self.selected_entry_title = None
        self.revealed_password_var.set("")
        self._clear_entry_form()
        self._clear_search()
        self._show_auth_view()
        self._set_status(f"{display_name}'s vault was encrypted and closed successfully.")

    def _on_close(self) -> None:
        if self.session is not None:
            try:
                lock_session(self.session)
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror(APP_TITLE, f"Could not encrypt the vault before closing.\n\n{exc}")
                return
        self.root.destroy()

    def _filtered_entries(self) -> list[dict[str, str]]:
        if self.session is None:
            return []
        needle = self.search_var.get().strip().lower()
        if not needle:
            return sorted(self.session.entries, key=lambda item: item["Title"].lower())
        return sorted(
            [entry for entry in self.session.entries if needle in entry["Title"].lower()],
            key=lambda item: item["Title"].lower(),
        )

    def _refresh_tree(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        for entry in self._filtered_entries():
            self.tree.insert(
                "",
                "end",
                iid=entry["Title"],
                values=(
                    entry["Title"],
                    shorten_for_table(entry["URL"], 42),
                    shorten_for_table(entry["Notes"], 52),
                ),
            )

        if self.selected_entry_title and self.tree.exists(self.selected_entry_title):
            self.tree.selection_set(self.selected_entry_title)
            self.tree.focus(self.selected_entry_title)

    def _clear_search(self) -> None:
        self.search_var.set("")
        self._refresh_tree()
        self._set_status("Search cleared.")

    def _on_tree_select(self, _event: object) -> None:
        selection = self.tree.selection()
        if not selection:
            return

        title = selection[0]
        self.selected_entry_title = title
        entry = self._selected_entry()
        if entry is None:
            return

        self.entry_title_var.set(entry["Title"])
        self.entry_url_var.set(entry["URL"])
        self.entry_password_var.set("")
        self._set_notes_text(entry["Notes"])
        self.revealed_password_var.set("")
        self._set_status("Entry loaded without revealing the password. Use Reveal only if you need to inspect it.")

    def _clear_entry_form(self) -> None:
        self.selected_entry_title = None
        self.entry_title_var.set("")
        self.entry_url_var.set("")
        self.entry_password_var.set("")
        self.revealed_password_var.set("")
        self._set_notes_text("")
        self.tree.selection_remove(self.tree.selection())
        self._set_status("Entry form cleared.")

    def _generate_password(self) -> None:
        try:
            length = int(self.generator_length_var.get())
        except ValueError:
            messagebox.showerror(APP_TITLE, "Password length must be a whole number.")
            return

        if length < 8 or length > 64:
            messagebox.showerror(APP_TITLE, "Generated passwords must be between 8 and 64 characters long.")
            return

        password = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))
        self.entry_password_var.set(password)
        self._set_status("Generated a random password and placed it in the password field.")

    def _add_entry(self) -> None:
        if self.session is None:
            return

        title = self.entry_title_var.get().strip()
        password = self.entry_password_var.get()
        url_value = self.entry_url_var.get().strip()
        notes = self._get_notes_text()

        if not title:
            messagebox.showerror(APP_TITLE, "Title cannot be empty.")
            return
        if not password:
            messagebox.showerror(APP_TITLE, "Password cannot be empty when adding a new entry.")
            return
        if self._find_entry_index_by_title(title) is not None:
            messagebox.showerror(APP_TITLE, "An entry with that title already exists.")
            return

        encrypted_password = encrypt_text_value(password, self.session.vault_key)
        self.session.entries.append(
            {
                "Title": title,
                "EncryptedPassword": encrypted_password,
                "URL": url_value,
                "Notes": notes,
            }
        )
        self._persist_entries()
        self.selected_entry_title = title
        self._refresh_tree()
        self.entry_password_var.set("")
        self.revealed_password_var.set("")
        self._set_status("New entry added. The password was encrypted before being stored in the CSV vault.")

    def _update_entry(self) -> None:
        if self.session is None:
            return

        lookup_title = self.selected_entry_title or self.entry_title_var.get().strip()
        if not lookup_title:
            messagebox.showerror(APP_TITLE, "Select an entry or enter its title before updating.")
            return

        index = self._find_entry_index_by_title(lookup_title)
        if index is None:
            messagebox.showerror(APP_TITLE, "No existing entry was found for that title.")
            return

        new_title = self.entry_title_var.get().strip()
        new_password = self.entry_password_var.get()
        new_url = self.entry_url_var.get().strip()
        new_notes = self._get_notes_text()

        if not new_title:
            messagebox.showerror(APP_TITLE, "Title cannot be empty.")
            return

        duplicate_index = self._find_entry_index_by_title(new_title)
        if duplicate_index is not None and duplicate_index != index:
            messagebox.showerror(APP_TITLE, "Another entry already uses that title.")
            return

        encrypted_password = self.session.entries[index]["EncryptedPassword"]
        if new_password:
            encrypted_password = encrypt_text_value(new_password, self.session.vault_key)

        self.session.entries[index] = {
            "Title": new_title,
            "EncryptedPassword": encrypted_password,
            "URL": new_url,
            "Notes": new_notes,
        }
        self._persist_entries()
        self.selected_entry_title = new_title
        self._refresh_tree()
        self.entry_password_var.set("")
        self.revealed_password_var.set("")
        self._set_status("Entry updated and saved. If a new password was provided, it was re-encrypted with AES.")

    def _delete_entry(self) -> None:
        if self.session is None:
            return

        lookup_title = self.selected_entry_title or self.entry_title_var.get().strip()
        if not lookup_title:
            messagebox.showerror(APP_TITLE, "Select an entry or enter its title before deleting.")
            return

        index = self._find_entry_index_by_title(lookup_title)
        if index is None:
            messagebox.showerror(APP_TITLE, "No existing entry was found for that title.")
            return

        entry_title = self.session.entries[index]["Title"]
        if not messagebox.askyesno(APP_TITLE, f"Delete the entry '{entry_title}'?"):
            return

        del self.session.entries[index]
        self._persist_entries()
        self._clear_entry_form()
        self._refresh_tree()
        self._set_status("Entry deleted and removed from the CSV vault.")

    def _reveal_selected_password(self) -> None:
        if self.session is None:
            return

        entry = self._selected_entry()
        if entry is None:
            messagebox.showerror(APP_TITLE, "Select an entry before revealing its stored password.")
            return

        try:
            password = decrypt_text_value(entry["EncryptedPassword"], self.session.vault_key)
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.revealed_password_var.set(password)
        self._set_status("Stored password revealed on request.")

    def _hide_revealed_password(self) -> None:
        self.revealed_password_var.set("")
        self._set_status("Revealed password hidden again.")

    def _copy_revealed_password(self) -> None:
        password = self.revealed_password_var.get()
        if not password:
            messagebox.showerror(APP_TITLE, "Reveal a password first before copying it to the clipboard.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()
        self._set_status("Revealed password copied to the clipboard.")


def main() -> None:
    bootstrap_storage()
    if CRYPTO_IMPORT_ERROR is not None:
        show_missing_dependency_error()
        return

    root = tk.Tk()
    PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
