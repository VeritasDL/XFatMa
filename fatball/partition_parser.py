import os
import logging
from pathlib import Path

# === Logging Setup ===
DEBUG_LOG_FILE = "fatx_debug.log"
logger = logging.getLogger("partition_parser")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler(DEBUG_LOG_FILE, mode="a", encoding="utf-8")
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(fh)

# === Constants ===
XTAF_MAGIC = b'XTAF'
XTAF_HEADER_SIZE = 0x10
FULL_HEADER_SIZE = 0x1000
SECTOR_SIZE = 512

# === Parser Class ===
class PartitionParser:
    def __init__(self, debug=False):
        self.debug = debug
    def is_valid_partition(self, header: bytes) -> bool:
        if len(header) < XTAF_HEADER_SIZE:
            return False
        if header[0:4] != XTAF_MAGIC:
            return False
        try:
            spc = int.from_bytes(header[0x08:0x0C], "big")
            root_cluster = int.from_bytes(header[0x0C:0x10], "big")
            return spc == 0x20 and root_cluster >= 1
        except Exception as e:
            if self.debug:
                logger.debug(f"ERROR {e}")
        return False
    def extract_partition_info(self, header: bytes) -> dict | None:
        if len(header) < XTAF_HEADER_SIZE:
            return None
        try:
            spc = int.from_bytes(header[0x08:0x0C], "big")
            root_cluster = int.from_bytes(header[0x0C:0x10], "big")
            return {"magic": "XTAF","sectors_per_cluster": spc,"cluster_size": spc * SECTOR_SIZE,"root_dir_first_cluster": root_cluster,}
        except Exception as e:
            if self.debug:
                logger.debug(f"ERROR {e}")
            return None

def read_partitions_from_file(path, parser=None):
    if parser is None:
        parser = PartitionParser(debug=True)
    path = Path(path).resolve()
    os.makedirs("logs", exist_ok=True)
    output_path = Path("logs/valid_partitions.bin")
    found = []
    if path.is_dir():
        for root, _, files in os.walk(path):
            for file in files:
                full_path = Path(root) / file
                if full_path.is_file():
                    found.extend(read_partitions_from_file(full_path, parser))
        return found
    try:
        with open(path, "rb") as f, open(output_path, "ab") as valid_out:
            data = f.read()
            for i in range(len(data) - XTAF_HEADER_SIZE):
                header = data[i : i + XTAF_HEADER_SIZE]
                if parser.is_valid_partition(header):
                    info = parser.extract_partition_info(header)
                    if info:
                        info["source_file"] = str(path)
                        info["offset"] = i
                        info["offset_hex"] = f"0x{i:X}"
                        valid_out.write(header)
                        found.append(info)
                        print(f"[XTAF] {i:X} | SPC {info['sectors_per_cluster']} | RootFC {info['root_dir_first_cluster'] + 1}")
    except Exception as e:
        print(f"Failed reading {path}: {e}")
    return found
