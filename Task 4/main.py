from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk


APP_TITLE = "Task 4 - RSA Digital Signature Launcher"
BASE_DIR = Path(__file__).resolve().parent


def gui_python_executable() -> str:
    current = Path(sys.executable)
    pythonw = current.with_name("pythonw.exe")
    if pythonw.exists():
        return str(pythonw)
    return str(current)


class LauncherApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("620x280")
        self.root.minsize(520, 250)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        self.status_var = tk.StringVar(value="Open the three applications, then run them in the order Verifier -> Proxy -> Signer.")

        self._build_ui()

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        frame = ttk.Frame(self.root, padding=18)
        frame.grid(sticky="nsew")
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Task 4 - RSA Digital Signature", font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        button_row = ttk.Frame(frame)
        button_row.grid(row=1, column=0, sticky="ew", pady=(18, 12))
        for column in range(4):
            button_row.columnconfigure(column, weight=1)

        ttk.Button(button_row, text="Open Application 1", command=lambda: self.launch("signer_app.py")).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(button_row, text="Open Application 2", command=lambda: self.launch("proxy_app.py")).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(button_row, text="Open Application 3", command=lambda: self.launch("verifier_app.py")).grid(
            row=0, column=2, sticky="ew", padx=6
        )
        ttk.Button(button_row, text="Open All", command=self.launch_all).grid(
            row=0, column=3, sticky="ew", padx=(6, 0)
        )

        steps = (
            "1. Start Application 3 and click Start Listening.\n"
            "2. Start Application 2 and click Start Listening.\n"
            "3. Start Application 1, enter a message, and click Sign And Send To Proxy.\n"
            "4. Optionally change the signature in Application 2, then forward it to Application 3."
        )
        ttk.Label(frame, text=steps, justify="left").grid(row=2, column=0, sticky="w")

        ttk.Label(frame, textvariable=self.status_var, anchor="w").grid(row=3, column=0, sticky="ew", pady=(18, 0))

    def launch(self, script_name: str) -> None:
        script_path = BASE_DIR / script_name
        try:
            subprocess.Popen([gui_python_executable(), str(script_path)], cwd=BASE_DIR)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not launch {script_name}.\n\n{exc}")
            return

        self.status_var.set(f"Launched {script_name}.")

    def launch_all(self) -> None:
        for script_name in ("verifier_app.py", "proxy_app.py", "signer_app.py"):
            self.launch(script_name)
        self.status_var.set("Launched all three applications.")


def main() -> None:
    root = tk.Tk()
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
