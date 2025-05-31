import tkinter as tk
from fatx_gui import FATXGui
from config_manager import ConfigManager
from theme_manager import ThemeManager
from dirent_parser import DirentParser, read_dirents_from_file
from file_scanner import FileScanner
from signature_carver import SignatureCarver
from partition_parser import PartitionParser, read_partitions_from_file
if __name__ == "__main__":
    root = tk.Tk()
    cfg = ConfigManager("settings.json")
    theme = ThemeManager(root, cfg)
    theme.load_theme(cfg.get("theme", "azure-dark"))

    app = FATXGui(
        root=root,
        config_mgr=cfg,
        theme_mgr=theme,
        parser=DirentParser(debug=cfg.get("debug", True)),
        scanner=FileScanner([".img", ".bin"]),
        carver=SignatureCarver("signatures.json", logs_enabled=cfg.get("logs_enabled", True))
    )
    root.mainloop()
