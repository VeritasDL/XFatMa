import os
from pathlib import Path

class FileScanner:
    def __init__(self, extensions=None, include_extensionless=True):
        self.extensions = set(ext.lower() for ext in extensions) if extensions else set()
        self.include_extensionless = include_extensionless

    def scan_files(self, paths):
        found = []
        for path in paths:
            path = Path(path)
            if path.is_file():
                ext = path.suffix.lower()
                if not self.extensions or ext in self.extensions or (self.include_extensionless and not ext):
                    found.append(path)
        return found

    def scan_directory(self, root: Path, recursive=True):
        found = []
        walker = os.walk(root) if recursive else [(root, [], os.listdir(root))]
        for base, _, files in walker:
            for name in files:
                path = Path(base) / name
                ext = path.suffix.lower()
                if not self.extensions or ext in self.extensions or (self.include_extensionless and not ext):
                    found.append(path)
        return found


def find_all_raw_files(root, extensions=None, include_extensionless=True, recursive=True):
    scanner = FileScanner(extensions=extensions, include_extensionless=include_extensionless)
    return scanner.scan_directory(Path(root), recursive=recursive)
