import logging
import os
DEBUG_LOG_FILE = "fatx_debug.log"
logger = logging.getLogger("dirent_parser")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler(DEBUG_LOG_FILE, mode="a", encoding="utf-8")
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(fh)

import struct
from datetime import datetime, date
DIRENT_SIZE = 0x40
DIRENT_FORMAT = '>BB42sLLLLL'  # name_len, attr, name[42], cluster, size, ts1, ts2, ts3
VALID_FILENAME_CHARS = (
    {0x20, 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2D, 0x2E, 0x5B, 0x5D, 0x5E, 0x5F, 0x60, 0x7B, 0x7D, 0x7E} |
    set(range(0x30, 0x3A)) | set(range(0x41, 0x5B)) | set(range(0x61, 0x7B)) | set(range(0x7F, 0x100))
)
INVALID_FILENAME_CHARS = set(range(0x00, 0x1F)) | set(ord(c) for c in '"*+,/:;<=>?\\|')
DIRENT_UNUSED_VALUES = {0x00, 0xFF}
DIRENT_DELETED_VALUE = 0xE5
VALID_FILE_ATTRIBUTES = {0x00, 0x01, 0x02, 0x04, 0x10, 0x20}

ATTR_NAMES = {
    0x00: "FILE",
    0x01: "READONLY",
    0x02: "HIDDEN",
    0x04: "SYSTEM",
    0x10: "DIRECTORY",
    0x20: "ARCHIVE",
}

class X360TimeStamp:
    def __init__(self, raw):
        self.raw = raw

    @property
    def year(self):
        return ((self.raw >> 25) & 0x7F) + 1980

    @property
    def month(self):
        return (self.raw >> 21) & 0xF

    @property
    def day(self):
        return (self.raw >> 16) & 0x1F

    @property
    def hour(self):
        return (self.raw >> 11) & 0x1F

    @property
    def minute(self):
        return (self.raw >> 5) & 0x3F

    @property
    def second(self):
        return (self.raw & 0x1F) * 2

    def __str__(self):
        try:
            return datetime(self.year, self.month, self.day, self.hour, self.minute, self.second).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return ""

class DirentParser:
    def __init__(self, debug=False):
        self.debug = debug
    def describe_attributes(self, attr: int) -> str:
        return ATTR_NAMES.get(attr, None)
        
    def decode_filename(self, data: bytes) -> str | None:
        try:
            name = data.split(b'\xff')[0].decode('ascii')
            if any(ord(c) not in VALID_FILENAME_CHARS or ord(c) in INVALID_FILENAME_CHARS for c in name):
                return None
            return name
        except UnicodeDecodeError:
            return None

    def is_valid_dirent(self, entry: bytes) -> bool:
        if len(entry) != DIRENT_SIZE:
            return False
        name_len, attr, name_field, *_ = struct.unpack(DIRENT_FORMAT, entry)
        if attr not in VALID_FILE_ATTRIBUTES:
            return False
        if name_len in DIRENT_UNUSED_VALUES or (name_len != DIRENT_DELETED_VALUE and name_len > 0x2A):
            return False
        filename = name_field[:name_len]
        padding = name_field[name_len:0x2A]
        if not all(c in VALID_FILENAME_CHARS for c in filename):
            return False
        expected_padding_len = 0x2A - name_len
        if len(padding) != expected_padding_len:
            return False
        if not all(p == 0xFF or p in VALID_FILENAME_CHARS for p in padding):
            return False
        cluster = struct.unpack_from('>L', entry, 0x2C)[0]
        if cluster <= 1 or cluster > 0x3C6A3D:
            return False
        return True

    def extract_dirent_info(self, entry: bytes):
        name_len, attr, name_field, cluster, size, ts1, ts2, ts3 = struct.unpack(DIRENT_FORMAT, entry)
        name = self.decode_filename(name_field)
        desc = self.describe_attributes(attr)
        if name is None:
            if self.debug:
                logger.debug(f'extract_dirent_info: Name None')
            return None
        if desc is None:
            if self.debug:
                logger.debug(f'extract_dirent_info: Unknown attr 0x{attr:02X}')
            return None
        name_len = entry[0]
        return {
            "name": name,
            "attr": attr,
            "cluster": cluster,
            "size": size,
            "created": str(X360TimeStamp(ts1)),
            "modified": str(X360TimeStamp(ts2)),
            "accessed": str(X360TimeStamp(ts3)),
            "attr_desc": desc,
            "name_len": name_len,
        }

    def is_valid_overwritten_dirent(self, entry: bytes) -> bool:
        if len(entry) != DIRENT_SIZE:
            return False
        name_len, attr, _, cluster, *_ = struct.unpack(DIRENT_FORMAT, entry)
        if attr not in VALID_FILE_ATTRIBUTES:
            return False
        filename_full = entry[2:2+0x2A]
        try:
            filename_full_ff_index = filename_full.index(0xFF)
        except ValueError:
            filename_full_ff_index = len(filename_full)
        filename = filename_full[:filename_full_ff_index]
        if any(c not in VALID_FILENAME_CHARS for c in filename):
            return False
        padding = entry[2+len(filename):0x2A]
        if not all(p == 0xFF or p in VALID_FILENAME_CHARS for p in padding):
            return False
        if cluster <= 1 or cluster > 0x3C6A3D:
            return False
        return True

    def extract_overwritten_dirent_info(self, entry: bytes):
        name_len, attr, _, cluster, size, ts1, ts2, ts3 = struct.unpack(DIRENT_FORMAT, entry)
        filename_full = entry[2:2+0x2A]
        try:
            filename_full_ff_index = filename_full.index(0xFF)
        except ValueError:
            filename_full_ff_index = len(filename_full)
        filename = filename_full[:filename_full_ff_index]
        try:
            filename_decoded = filename.decode('ascii')
        except UnicodeDecodeError:
            return None
        if any(ord(c) not in VALID_FILENAME_CHARS or ord(c) in INVALID_FILENAME_CHARS for c in filename_decoded):
            return None
        desc = self.describe_attributes(attr)
        if desc is None:
            return None
        name_len = entry[0]
        return {
            "name": filename_decoded,
            "attr": attr,
            "cluster": cluster,
            "size": size,
            "created": str(X360TimeStamp(ts1)),
            "modified": str(X360TimeStamp(ts2)),
            "accessed": str(X360TimeStamp(ts3)),
            "attr_desc": desc,
            "name_len": name_len,
        }

def read_dirents_from_file(filepath, parser=None):
    if parser is None:
        parser = DirentParser(debug=True)

    entries = []
    path = os.path.abspath(filepath)
    valid_path = os.path.join("logs", "valid_dirents.bin")
    overwritten_path = os.path.join("logs", "overwritten_dirents.bin")

    os.makedirs("logs", exist_ok=True)
    with open(filepath, "rb") as f, open(valid_path, "ab") as valid_out, open(overwritten_path, "ab") as overwritten_out:
        data = f.read()
        i = 0
        while i < len(data) - DIRENT_SIZE:
            matched = False
            for offset in (0, 4, 8, 12):
                pos = i + offset
                if pos + DIRENT_SIZE > len(data):
                    continue
                dirent = data[pos:pos+DIRENT_SIZE]
                if parser.is_valid_dirent(dirent):
                    info = parser.extract_dirent_info(dirent)
                    if info:
                        info["source_file"] = filepath
                        info["offset"] = pos
                        entries.append(info)
                        valid_out.write(dirent)
                        i = pos + DIRENT_SIZE
                        matched = True
                        break
                elif parser.is_valid_overwritten_dirent(dirent):
                    info = parser.extract_overwritten_dirent_info(dirent)
                    if info:
                        info["source_file"] = filepath
                        info["offset"] = pos
                        entries.append(info)
                        overwritten_out.write(dirent)
                        i = pos + DIRENT_SIZE
                        matched = True
                        break
            if not matched:
                i += 1
    return entries
