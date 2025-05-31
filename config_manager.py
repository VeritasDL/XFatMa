import json
from pathlib import Path
import os
import sys
DEFAULT_SETTINGS = {
    "hxd_path": "C:\\Program Files\\HxD\\HxD.exe",
    "preview_bytes": 1024,
    "carving_step": 2000,
    "logs_enabled": True,
    "log_path": "logs",
    "signatures_path": "",
    "debug": True,
    "theme_file": "dark",
    "de_dupe_dirents": True,
}
def resource_path(filename):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.abspath(filename)
SETTINGS_FILE = resource_path("settings.json")
class ConfigManager:
    def __init__(self, config_path: Path):
        self.config_path = Path(config_path)
        self.settings = DEFAULT_SETTINGS.copy()
        self.load()

    def load(self):
        if not os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "w") as f:
                json.dump(DEFAULT_SETTINGS, f, indent=2)
        with open(SETTINGS_FILE, "r") as f:
            user_settings = json.load(f)
        self.settings.update(user_settings)
    def save(self):
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=2)

    def get(self, key, default=None):
        return self.settings.get(key, default)


    def set(self, key, value):
        if key in DEFAULT_SETTINGS:
            self.settings[key] = value
            self.save()
        else:
            print(f" Unknown config key: {key}")

    def all(self):
        return self.settings.copy()
