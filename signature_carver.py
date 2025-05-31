import os
import json
import time
from pathlib import Path

ZIP_EOCD = b"\x50\x4B\x05\x06"

class SignatureCarver:
    def __init__(self, sig_path=None, logs_enabled=True, config=None):
        if sig_path is None and config:
            sig_path = config.get("signatures_path", "signatures.json")
        self.sig_path = sig_path
        self.logs_enabled = logs_enabled
        self.signatures = self.load_signatures(self.sig_path)

    def log(self, message: str, log_path: Path):
        if self.logs_enabled:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(message + "\n")

    def load_signatures(self, json_path) -> dict:
        with open(json_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                assert isinstance(data, dict)
                for v in data.values(): assert 'magic' in v and 'ext' in v
                return data
            except Exception as e:
                raise ValueError(f"Invalid signature file {json_path}: {e}")

    def find_zip_end(self, data: bytes, start: int) -> int:
        max_search = min(len(data) - start, 0x500000)
        for i in range(start, start + max_search - 4):
            if data[i:i+4] == ZIP_EOCD:
                return i + 22
        return start + 0x200000

    def carve_signatures(
        self,
        file_path: Path,
        output_dir: Path,
        step=0x1000,
        cancel_callback=lambda: False,
        filename_prefix="carved",
        override_ext=None
    ) -> dict:
        found = {}
        timestamp = time.strftime("carve_%Y%m%d-%H%M%S.log")
        log_file = Path(output_dir) / timestamp

        with open(file_path, "rb") as f:
            data = f.read()
            for i in range(0, len(data) - 16, step):
                if cancel_callback():
                    self.log('[!] Carving cancelled by user.', log_file)
                    return found
                for name, sig in self.signatures.items():
                    magic = bytes.fromhex(sig["magic"])
                    if data[i + sig["offset"]: i + sig["offset"] + len(magic)] == magic:
                        size = sig.get("size", 0x80000)
                        if sig.get("scan_footer") and name == "zip":
                            size = self.find_zip_end(data, i) - i
                        ext = override_ext or sig["ext"]
                        out_name = f"{filename_prefix}_{name}_{i:08X}{ext}"
                        out_path = Path(output_dir) / out_name
                        with open(out_path, "wb") as out:
                            out.write(data[i:i+size])
                        self.log(f"[+] {out_name} ({size} bytes)", log_file)
                        found[name] = found.get(name, 0) + 1
                        break
        return found
