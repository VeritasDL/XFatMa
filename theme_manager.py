
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
import os
import json
import sys
import shutil

def resource_path(filename):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.abspath(filename)

class ThemeManager:
    def __init__(self, root: tk.Tk, config, default="dark", theme_file=None):
        self.root = root
        self.config = config
        self.theme_dir = Path(resource_path("themes"))
        self.theme_dir.mkdir(exist_ok=True)
        self.current_theme = None
        theme_from_cfg = self.config.get("theme_file")
        self.theme_file = self.theme_dir / theme_from_cfg
        self.load_theme(self.config.get("theme_file", default))

    def load_theme(self, preference: str):
        try:
            self.root.tk.call("source", str(self.theme_file))
            theme_name = "azure-dark" if "dark" in self.theme_file.name.lower() else "azure-light"
            self.root.tk.call("ttk::setTheme", theme_name)
        except tk.TclError as e:
            print(f"[ThemeManager] Theme file: {e} lol")
            return
        self.current_theme = preference
        self.config.set("theme_file", preference)
    def list_available_themes(self):
        return sorted({f.name for f in self.theme_dir.glob("*.tcl") if f.is_file()})
    def add_theme_selector(self, parent: tk.Widget):
        themes = self.list_available_themes()
        if not themes:
            return
        def apply_theme(selected):
            self.theme_file = self.theme_dir / selected
            self.config.set("theme_file", selected)
            self.load_theme(selected)
        frame = ttk.Frame(parent)
        frame.pack(pady=5, padx=5, anchor="w")
        ttk.Label(frame, text="Theme:").pack(side="left")
        combo = ttk.Combobox(frame, values=themes, state="readonly")
        current_file = self.theme_file.name
        combo.set(current_file if current_file in themes else themes[0])
        combo.pack(side="left", padx=5)
        combo.bind("<<ComboboxSelected>>", lambda e: apply_theme(combo.get()))
        def browse_custom_theme():
            file_path = filedialog.askopenfilename(title="Select Theme", filetypes=[("TCL Files", "*.tcl")])
            if file_path:
                theme_name = os.path.basename(file_path)
                target_path = self.theme_dir / theme_name
                if not target_path.exists():
                    shutil.copy(file_path, target_path)
                themes = self.list_available_themes()
                combo["values"] = themes
                combo.set(theme_name)
                apply_theme(theme_name)
        ttk.Button(frame, text="Browse Custom Theme", command=browse_custom_theme).pack(side="left", padx=5)
