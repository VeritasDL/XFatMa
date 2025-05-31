import logging
with open("fatx_debug.log", "w", encoding="utf-8"): pass  # clear old log
logger = logging.getLogger("dirent_parser")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler("fatx_debug.log", mode="a", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(fh)
diff_logger = logging.getLogger("dupe_diff")
diff_logger.setLevel(logging.DEBUG)
if not diff_logger.hasHandlers():
    fh_diff = logging.FileHandler("fatx_diffs.log", mode="w", encoding="utf-8")
    fh_diff.setFormatter(logging.Formatter("%(message)s"))
    diff_logger.addHandler(fh_diff)
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    TkinterDnD = None
    print("Drag-and-drop support requires tkinterdnd2. Install via pip.")

import tkinter as tk
import threading
import queue
from tkinter import ttk, filedialog, messagebox, simpledialog
import os, json
from config_manager import ConfigManager
from file_scanner import FileScanner, find_all_raw_files
from dirent_parser import DirentParser, read_dirents_from_file
from partition_parser import PartitionParser, read_partitions_from_file
from signature_carver import SignatureCarver
from theme_manager import ThemeManager
from collections import defaultdict
import tkinter.font as tkFont
def human_readable_size(size):
    for unit in ['B','KB','MB','GB','TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"
def show_duplicate_info(self):
    for item_id in self.tree.get_children():
        name = self.tree.set(item_id, "name")
        count = self.duplicate_counts.get(name, 0)
        if count > 1:
            new_name = f"{name} [{count}]"
            self.tree.set(item_id, "name", new_name)
def get_entry_signature(entry):
    return (
        entry.get("name"),
        entry.get("cluster"),
        entry.get("size"),
        str(entry.get("deleted")).lower(),
        entry.get("attr_desc", "").strip().lower(),
        entry.get("created", "").strip(),
        entry.get("modified", "").strip(),
        entry.get("accessed", "").strip(),
    )
class FATXGui:
    COLUMN_CONFIG = [
        ("name", "Name"),
        ("cluster", "Cluster"),
        ("size", "Size"),
        ("deleted", "Deleted"),
        ("attr", "Type"),
        ("created", "Created"),
        ("modified", "Modified"),
        ("accessed", "Accessed"),
    ]
    def __init__(self, root):
        self.column_keys = [key for key, _ in self.COLUMN_CONFIG]
        self.root = root
        # Setup ThemeManager
        self.config = ConfigManager("settings.json")
        self.theme_manager = ThemeManager(self.root, self.config)
        self.root.title("FATX MaBalls")
        self.entries = []
        self.sort_state = {}
        self.deleted_count = 0
        self.scanning = False
        self.parser = DirentParser()
        style = ttk.Style()
        tree_frame = ttk.Frame(root)
        tree_frame.pack(fill="both", expand=True)
        style.configure("Treeview", borderwidth=1, relief="solid")
        style.configure("Treeview.Heading", borderwidth=1, relief="solid")
        self.tree = ttk.Treeview(tree_frame, columns=self.column_keys, show="headings")
        self.tree["displaycolumns"] = self.column_keys
        self.entry_sig_map = {}
        self.duplicate_counts = defaultdict(int)
        self.font = tkFont.Font()
        self.status_label = None
        for key, label in self.COLUMN_CONFIG:
            width = self.font.measure(label)
            self.tree.heading(key, text=label, command=lambda c=key: self.sort_by_column(c, False))
            self.tree.column(key, width=width, anchor="w", stretch=True)

        self.tree.tag_configure("deleted", foreground="white", background="#d9534f")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self.preview_hex)
        self.tree.bind("<Button-3>", self.on_right_click)

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Hex Preview", command=self.menu_preview)
        self.menu.add_command(label="Open in Explorer", command=self.menu_explorer)
        self.menu.add_command(label="Open in HxD", command=self.menu_hxd)

        self.build_menu()
        self.setup_search()

    def on_right_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        print(f"Right-click at ({event.x}, {event.y}) in region: {region}")

        if region == "heading":
            ctrl_pressed = (event.state & 0x0004) != 0

            if ctrl_pressed:
                menu = tk.Menu(self.root, tearoff=0)
                menu.add_command(label="Reset Columns", command=self.reset_column_visibility)
                menu.tk_popup(event.x_root, event.y_root)
                return

            col_id = self.tree.identify_column(event.x)
            col_index = int(col_id.replace("#", "")) - 1
            if 0 <= col_index < len(self.COLUMN_CONFIG):
                key = self.COLUMN_CONFIG[col_index][0]
                print(f"Header clicked: column_id={col_id}, index={col_index}, key={key}")
                self.toggle_column_visibility(key)

        elif region in ("cell",):
            row_id = self.tree.identify_row(event.y)
            if row_id:
                self.tree.selection_set(row_id)
                self.menu.post(event.x_root, event.y_root)

    def reset_column_visibility(self):
        full_columns = [key for key, _ in self.COLUMN_CONFIG]
        self.tree["displaycolumns"] = full_columns
        print(f"Columns reset to: {full_columns}")
    def is_duplicate_entry(self, entry):
        sig = get_entry_signature(entry)
        sig_key = tuple(sig)
        if sig_key in self.entry_sig_map:
            self.duplicate_counts[sig_key] += 1
            original = self.entry_sig_map[sig_key]
            entry_name = entry.get("name", "<Unnamed>")
            source = entry.get("source_file", "unknown")
            offset = entry.get("offset", "N/A")
            diff_logger.debug(f"\nDUPLICATE {entry_name} {hex(entry.get('cluster', 0))}")
            diff_logger.debug(f"Source: {source} | Offset: {offset}")
            diff_logger.debug("Signature key:")
            for i, val in enumerate(sig_key):
                diff_logger.debug(f"  [{i}] {val!r}")
            compared = {
                "Name": (original.get("name"), entry.get("name")),
                "Cluster": (original.get("cluster"), entry.get("cluster")),
                "Size": (original.get("size"), entry.get("size")),
                "Deleted": (str(original.get("deleted")).lower(), str(entry.get("deleted")).lower()),
                "Attr": (original.get("attr_desc", "").strip().lower(), entry.get("attr_desc", "").strip().lower()),
                "Created": (original.get("created", "").strip(), entry.get("created", "").strip()),
                "Modified": (original.get("modified", "").strip(), entry.get("modified", "").strip()),
                "Accessed": (original.get("accessed", "").strip(), entry.get("accessed", "").strip()),
            }
            diff_logger.debug("FIELD COMPARISON:")
            for field, (val1, val2) in compared.items():
                match = "+" if val1 == val2 else "X"
                diff_logger.debug(f"  {field:<9}: {val1!r} vs {val2!r}  => {match}")
            return True, self.duplicate_counts[sig_key], entry_name
        self.entry_sig_map[sig_key] = entry
        self.duplicate_counts[sig_key] = 0
        return False, 0, entry.get("name", "<Unnamed>")

    def get_deleted_entries(self):
        deleted_entries = []
        try:
            deleted_col_index = self.column_keys.index("deleted")
        except ValueError:
            return deleted_entries
        for item_id in self.tree.get_children():
            try:
                values = self.tree.item(item_id).get("values", [])
                if str(values[deleted_col_index]).lower() == "true":
                    deleted_entries.append(item_id)
            except Exception:
                continue
        return deleted_entries

    def highlight_deleted_entries(self):
        for item_id in self.get_deleted_entries():
            self.tree.item(item_id, tags=("deleted",))


    def sort_by_column(self, col, reverse):
        data = [
            (self.tree.set(k, col), k)
            for k in self.tree.get_children("")
        ]
        try:
            if col == "cluster":
                data.sort(
                    key=lambda t: int(t[0], 16) if t[0].startswith("0x") else int(t[0]),
                    reverse=reverse
                )
            elif col == "size":
                data.sort(
                    key=lambda t: int(t[0], 16) if t[0].startswith("0x") else float(t[0].replace(',', '').replace(' KB', '').replace(' MB', '').replace(' GB', '').replace(' TB', '')),
                    reverse=reverse
                )
            elif col == "deleted":
                data.sort(
                    key=lambda t: t[0].lower() in {"true", "yes"},
                    reverse=reverse
                )
            elif col in {"created", "modified", "accessed"}:
                data.sort(
                    key=lambda t: datetime.strptime(t[0], "%Y-%m-%d %H:%M:%S") if t[0] else datetime.min,
                    reverse=reverse
                )
            else:
                data.sort(
                    key=lambda t: t[0].lower(),
                    reverse=reverse
                )
        except (ValueError, TypeError):
            data.sort(reverse=reverse)

        for idx, (_, k) in enumerate(data):
            self.tree.move(k, '', idx)

        self.sort_state[col] = not reverse
        self.tree.heading(col, command=lambda: self.sort_by_column(col, self.sort_state[col]))

    def set_column_visible(self, col):
        current = list(self.tree["displaycolumns"])
        if col not in current:
            current.append(col)
            ordered = [k for k, _ in self.COLUMN_CONFIG if k in current]
            self.tree["displaycolumns"] = ordered

    def set_column_invisible(self, col):
        current = list(self.tree["displaycolumns"])
        if col in current:
            if len(current) == 1:
                print("Warning: At least one column must remain visible.")
                return
            current.remove(col)
            self.tree["displaycolumns"] = current

    def auto_resize_columns(self):
        font = tkFont.Font()
        for col in self.tree["columns"]:
            max_width = font.measure(col)
            for item in self.tree.get_children():
                cell_text = self.tree.set(item, col)
                max_width = max(max_width, font.measure(cell_text))
            self.tree.column(col, width=max_width)

    def setup_search(self):
        self.root.bind("<Control-f>", lambda e: self.show_search_bar())

    def show_search_bar(self):
        if hasattr(self, 'search_frame') and self.search_frame.winfo_exists():
            return
        self.search_frame = tk.Frame(self.root, bg="#e9e9e9", relief="groove", borderwidth=1)
        self.search_frame.pack(side="bottom", fill="x")

        tk.Label(self.search_frame, text="Search:").pack(side="left", padx=5, pady=4)

        self.search_column = tk.StringVar(value="name")
        column_menu = ttk.Combobox(self.search_frame, textvariable=self.search_column, state="readonly")
        column_menu['values'] = [k for k, _ in self.COLUMN_CONFIG]
        column_menu.pack(side="left", padx=5)

        entry = tk.Entry(self.search_frame)
        entry.pack(side="left", fill="x", expand=True, padx=5)
        entry.focus()

        self.fuzzy_var = tk.BooleanVar(value=True)
        fuzzy_check = tk.Checkbutton(self.search_frame, text="Fuzzy", variable=self.fuzzy_var)
        fuzzy_check.pack(side="left", padx=5)

        self.match_label = tk.Label(self.search_frame, text="0 matches")
        self.match_label.pack(side="left", padx=10)

        close_btn = tk.Button(self.search_frame, text="✕", command=self.clear_search_bar, bd=0)
        close_btn.pack(side="right", padx=5)

        def do_filter(*_):
            text = entry.get().strip().lower()
            selected_col = self.search_column.get()
            self.tree.delete(*self.tree.get_children())
            matches = 0
            for e in self.entries:
                val = str(e.get(selected_col, "")).lower()
                if (self.fuzzy_var.get() and text in val) or (not self.fuzzy_var.get() and val.startswith(text)):
                    self.insert_entry(e)
                    matches += 1
            self.match_label.config(text=f"{matches} matches")

        entry.bind("<KeyRelease>", do_filter)
        entry.bind("<Return>", do_filter)
        entry.bind("<Escape>", lambda e: self.clear_search_bar())

    def clear_search_bar(self):
        if hasattr(self, 'search_frame') and self.search_frame.winfo_exists():
            self.search_frame.destroy()
            self.tree.delete(*self.tree.get_children())
            for e in self.entries:
                self.insert_entry(e)


    def start_threaded_scan(self, mode="folder"):
        self.scan_queue = queue.Queue()
        self.entries.clear()
        self.entry_signatures.clear()
        self.tree.delete(*self.tree.get_children())
        self.deleted_count = 0
        self.status_label = tk.Label(self.root, text="Scanning", fg="blue")
        self.status_label.pack(pady=5)
        self.root.update()
        path = filedialog.askdirectory() if mode == "folder" else filedialog.askopenfilename()
        if not path:
            self.status_label.destroy()
            return
        t = threading.Thread(target=self._scan_worker, args=(path, mode))
        t.daemon = True
        t.start()
        self.root.after(100, self._check_scan_done)

    def _scan_worker(self, path, mode):
        files = find_all_raw_files(path) if mode == "folder" else [path]
        for f in files:
            for entry in read_dirents_from_file(f):
                self.scan_queue.put(entry)
        self.scan_queue.put(None)
    def _check_scan_done(self):
        try:
            dedupe_enabled = self.config.get("de_dupe_dirents", True)

            while True:
                entry = self.scan_queue.get_nowait()
                if entry is None:
                    self.status_label.config(text=f"Scan complete: {len(self.entries)} entries, Deleted: {self.deleted_count}")
                    self.highlight_deleted_entries()
                    self.show_duplicate_info(sum(self.duplicate_counts.values()))
                    return

                is_dupe, dupes, display_name = (False, 0, entry.get("name", "<Unnamed>"))
                if dedupe_enabled:
                    is_dupe, dupes, display_name = self.is_duplicate_entry(entry)
                    if is_dupe:
                        continue

                entry_name = display_name.strip()
                if dupes:
                    tempma = entry.get("#0", entry.get("name", "<Unnamed>"))
                    # print(f"[DEBUG] Pre-dupe name: {tempma}")
                    entry_name += f" [dupes:{dupes}]"
                else:
                    tempma = entry.get("#0", entry.get("name", "<Unnamed>"))
                    # print(f"[DEBUG] No dupes: {tempma} | dupes={dupes}")

                entry["#0"] = entry_name
                self.entries.append(entry)
                item_id = self.insert_entry(entry)

                if dedupe_enabled and dupes:
                    # print(f"[DEBUG] Tagged as dupe: {entry_name} | dupes={dupes}")
                    self.tree.item(item_id, tags=("dupe",))

        except queue.Empty:
            self.root.after(100, self._check_scan_done)



    def build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Dirent Scan Folder", command=self.scan_folder)
        file_menu.add_command(label="Dirent Scan File", command=self.scan_file)
        file_menu.add_command(label="Partition Scan Folder", command=self.partition_scan_folder)
        file_menu.add_command(label="Partition Scan File", command=self.partition_scan_file)
        file_menu.add_command(label="Recover Selected", command=self.recover_selected)
        file_menu.add_command(label="Run File Carving", command=self.carve_menu)
        file_menu.add_command(label="Open Last Carve Log", command=self.open_last_log)
        file_menu.add_separator()
        file_menu.add_command(label="Edit Carving Signatures", command=self.edit_signatures)
        file_menu.add_command(label="Preferences", command=self.edit_settings)
        file_menu.add_command(label="Theme Settings", command=self.open_theme_selector)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)
    
    def insert_entry(self, entry):
        label = entry.get("name", "<Unnamed>")
        tag = ""
        if entry.get("name_len") == 0xE5:
            self.deleted_count += 1
            tag = "deleted"

        cluster = entry.get("cluster", 0)
        size = entry.get("size", 0)
        attr_desc = entry.get("attr_desc", "")
        created = entry.get("created", "")
        modified = entry.get("modified", "")
        accessed = entry.get("accessed", "")

        size_str = "" if attr_desc == "DIRECTORY" else human_readable_size(size)
        deleted_str = "True" if tag == "deleted" else ""

        item_id = self.tree.insert(
            "", "end",
            values=(
                label,
                cluster,
                size_str,
                deleted_str,
                attr_desc,
                created,
                modified,
                accessed,
            ),
            tags=(tag,)
        )
        return item_id

    def partition_scan_folder(self):
        folder = filedialog.askdirectory(title="Select Folder for Partition Scan")
        if not folder:
            return
        files = find_all_raw_files(folder)
        for f in files:
            read_partitions_from_file(f)

    def partition_scan_file(self):
        path = filedialog.askopenfilename(title="Select File for Partition Scan")
        if not path:
            return
        read_partitions_from_file(path)

    def scan_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.entries.clear()
        self.tree.delete(*self.tree.get_children())
        self.deleted_count = 0
        dedupe_enabled = self.config.get("de_dupe_dirents", True)

        files = find_all_raw_files(folder)
        for f_idx, f in enumerate(files):
            for entry in read_dirents_from_file(f):
                is_dupe, dupes, display_name = (False, 0, entry.get("name", "<Unnamed>"))
                if dedupe_enabled:
                    is_dupe, dupes, display_name = self.is_duplicate_entry(entry)
                    if is_dupe:
                        continue

                entry_name = display_name.strip()
                if dupes:
                    entry_name += f" [dupes:{dupes}]"

                entry["#0"] = entry_name
                self.entries.append(entry)
                item_id = self.insert_entry(entry)

                if dedupe_enabled and dupes:
                    self.tree.item(item_id, tags=("dupe",))

        print(f"Total files: {len(self.entries)}\nDeleted entries: {self.deleted_count}")

    def scan_file(self):
        path = filedialog.askopenfilename(title="Select File")
        if not path:
            return
        self.entries.clear()
        self.tree.delete(*self.tree.get_children())
        self.deleted_count = 0
        dedupe_enabled = self.config.get("de_dupe_dirents", True)

        for entry in read_dirents_from_file(path):
            is_dupe, dupes, display_name = (False, 0, entry.get("name", "<Unnamed>"))
            if dedupe_enabled:
                is_dupe, dupes, display_name = self.is_duplicate_entry(entry)
                if is_dupe:
                    continue

            entry_name = display_name.strip()
            if dupes:
                entry_name += f" [dupes:{dupes}]"

            entry["#0"] = entry_name
            self.entries.append(entry)
            item_id = self.insert_entry(entry)

            if dedupe_enabled and dupes:
                self.tree.item(item_id, tags=("dupe",))

        print(f"File: {os.path.basename(path)}\nEntries: {len(self.entries)}\nDeleted: {self.deleted_count}")

    def recover_selected(self):
        out = filedialog.askdirectory(title="Select Output Folder")
        selected = self.tree.selection()
        for sid in selected:
            index = self.tree.index(sid)
            entry = self.entries[index]
            recover_best_effort(entry, out)
        print(f"Recovered {len(selected)} file(s)")

    def preview_hex(self, _):
        selection = self.tree.selection()
        if not selection:
            return
        item_id = selection[0]
        entry = self.tree.item(item_id, "values")
        try:
            idx = self.tree.index(item_id)
            entry_data = self.entries[idx]
            source_file = entry_data.get("source_file")
            if not source_file or not os.path.exists(source_file):
                raise FileNotFoundError(f"Source file not found: {source_file}")

            with open(source_file, "rb") as f:
                offset_val = entry_data.get("offset")
                if not isinstance(offset_val, int):
                    raise ValueError("Missing or invalid offset for dirent preview")
                f.seek(offset_val)
                data = f.read(0x40)

            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_bytes = ' '.join(f"{b:02X}" if not (i == 0 and j in (0x0B, 0x0C)) else f"\x1b[91m{b:02X}\x1b[0m" for j, b in enumerate(chunk))
                ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hex_lines.append(f"{offset_val+i:08X}  {hex_bytes:<48}  {ascii}")

            win = tk.Toplevel(self.root, bg="#1e1e1e")
            win.title(f"Hex: {entry_data.get('name', '')}")
            win.geometry("700x400")
            win.configure(bg="#1e1e1e")

            txt = tk.Text(win, wrap="none", font=("Courier", 10), bg="#1e1e1e", fg="#dcdcdc")
            for line in hex_lines:
                txt.insert("end", line + "\n")
            txt.config(state="disabled")

            vsb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
            hsb = ttk.Scrollbar(win, orient="horizontal", command=txt.xview)
            txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

            txt.pack(side="left", fill="both", expand=True)
            vsb.pack(side="right", fill="y")
            hsb.pack(side="bottom", fill="x")

            def copy_to_clipboard():
                win.clipboard_clear()
                win.clipboard_append(txt.get("1.0", "end-1c"))

            def export_to_file():
                file_path = filedialog.asksaveasfilename(title="Save Hex View", defaultextension=".txt",
                                                         filetypes=[("Text Files", "*.txt")])
                if file_path:
                    with open(file_path, "w", encoding="utf-8") as out:
                        out.write(txt.get("1.0", "end-1c"))

            btn_frame = tk.Frame(win, bg="#1e1e1e")
            btn_frame.pack(side="bottom", pady=4)
            tk.Button(btn_frame, text="Copy", command=copy_to_clipboard).pack(side="left", padx=5)
            tk.Button(btn_frame, text="Export", command=export_to_file).pack(side="left", padx=5)

            cluster = entry_data.get("cluster", "?")
            offset_hex = f"0x{offset_val:X}"
            win.title(f"Hex: {entry_data.get('name', '')} | Cluster: {cluster} | Offset: {offset_hex}")

        except Exception as e:
            print("Error", f"Failed to preview: {e}")

    def carve_menu(self):
        folder = filedialog.askdirectory(title="Folder to Scan")
        output = filedialog.askdirectory(title="Output for Carved Files")
        carver = SignatureCarver(config=self.config)
        stats = carve_signatures(folder, output)
        lines = [f"{k}: {v}" for k, v in stats.items()]
        print("Carving Complete", "\n".join(lines) if lines else "No files carved")

    def open_last_log(self):
        try:
            logs = sorted(os.listdir(LOG_PATH), reverse=True)
            for file in logs:
                if file.endswith(".log") or file.endswith(".deleted.txt"):
                    os.startfile(os.path.join(LOG_PATH, file))
                    return
            print("No Logs", "No carve logs found.")
        except Exception as e:
            print("Error", str(e))

    def edit_signatures(self):
        win = tk.Toplevel(self.root, bg="#1e1e1e")
        win.configure(bg="#1e1e1e")
        win.title("Signature Editor")
        win.geometry("600x400")
        with open("signatures.json", "r") as f:
            sigs = json.load(f)
        tree = ttk.Treeview(win, columns=("name", "magic", "ext", "offset", "size"), show="headings")
        for col in ("name", "magic", "ext", "offset", "size"):
            tree.heading(col, text=col)
        tree.pack(fill="both", expand=True)
        for name, d in sigs.items():
            tree.insert("", "end", values=(name, d["magic"], d["ext"], d.get("offset", 0), d.get("size", 0)))
        tree.bind("<Double-1>", lambda e: self.preview_sig_hex(tree.focus(), sigs, tree))

        def add_sig():
            name = simpledialog.askstring("Name", "Name?")
            magic = simpledialog.askstring("Magic", "Magic (hex)?")
            ext = simpledialog.askstring("Ext", "Extension (e.g. .xex)?")
            offset = simpledialog.askinteger("Offset", "Offset?")
            size = simpledialog.askinteger("Size", "Size?")
            if name and magic and ext:
                sigs[name] = {"magic": magic, "ext": ext, "offset": offset or 0, "size": size or 0}
                tree.insert("", "end", values=(name, magic, ext, offset or 0, size or 0))

    def preview_sig_hex(self, selected_item, sigs, tree):
        item = tree.item(selected_item)
        name = item["values"][0]
        magic = sigs[name]["magic"]
        try:
            b = bytes.fromhex(magic)
            hex_lines = []
            for i in range(0, len(b), 16):
                chunk = b[i:i+16]
                hex_str = ' '.join(f"{x:02X}" for x in chunk)
                ascii = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
                hex_lines.append(f"{i:08X}  {hex_str:<48}  {ascii}")
            win = tk.Toplevel(self.root, bg="#1e1e1e")
            win.configure(bg="#1e1e1e")
            win.title(f"Magic: {name}")
            txt = tk.Text(win, font=("Courier", 10))
            txt.insert("1.0", "\n".join(hex_lines))
            txt.config(state="disabled")
            txt.pack(fill="both", expand=True)
        except Exception as e:
            print("Invalid Hex", str(e))

    def context_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.menu.post(event.x_root, event.y_root)

    def menu_preview(self):
        self.preview_hex(None)

    def menu_explorer(self):
        selection = self.tree.selection()
        if not selection:
            return
        item_id = selection[0]
        idx = self.tree.index(item_id)
        source_file = self.entries[idx].get("source_file")
        if not source_file or not os.path.exists(source_file):
            messagebox.showwarning("File Not Found", f"Source file not found: {source_file}")
            return
        path = os.path.abspath(source_file)
        os.system(f'explorer /select,"{path}"')

    def menu_hxd(self):
        selection = self.tree.selection()
        if not selection:
            return
        item_id = selection[0]
        idx = self.tree.index(item_id)
        entry_data = self.entries[idx]
        file = os.path.abspath(entry_data.get("source_file", ""))
        offset = entry_data.get("offset")
        if not file or not os.path.exists(file):
            messagebox.showwarning("File Not Found", f"Source file not found: {file}")
            return
        hxd_path = self.config.get("hxd_path")
        if os.path.exists(hxd_path):
            os.system(f'"{hxd_path}" "{file}" /offset:{offset}')
        else:
            print("HxD Not Found", f"HxD not found at: {hxd_path}")

    def edit_settings(self):
        with open("settings.json", "r") as f:
            settings = json.load(f)

        def save():
            for item in tree.get_children():
                key, val = tree.item(item, "values")
                if key in settings:
                    try:
                        if key in ["logs_enabled", "debug", "de_dupe_dirents"]:
                            settings[key] = val.lower() in ("1", "true", "yes", "on")
                        elif key in ["preview_bytes", "carving_step"]:
                            settings[key] = int(val)
                        else:
                            settings[key] = val
                    except ValueError:
                        messagebox.showwarning("Invalid Input", f"Invalid value for {key}: {val}")
                        return
            with open("settings.json", "w") as f:
                json.dump(settings, f, indent=2)
            win.destroy()

        def edit_cell(event):
            item = tree.identify_row(event.y)
            column = tree.identify_column(event.x)
            if column != '#2' or not item:
                return
            x, y, width, height = tree.bbox(item, column)
            old_value = tree.set(item, "Value")
            entry = tk.Entry(win)
            entry.place(x=x + 10, y=y + 10, width=width)
            entry.insert(0, old_value)
            entry.focus()
            def save_edit(e):
                tree.set(item, "Value", entry.get())
                entry.destroy()
            entry.bind("<Return>", save_edit)
            entry.bind("<FocusOut>", lambda e: entry.destroy())
        win = tk.Toplevel(self.root)
        win.title("Preferences")
        win.geometry("600x300")
        win.configure(bg="#1e1e1e")
        tree = ttk.Treeview(win, columns=("Setting", "Value"), show="headings")
        tree.heading("Setting", text="Setting")
        tree.heading("Value", text="Value")
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        tree.bind("<Double-1>", edit_cell)
        for key, val in settings.items():
            tree.insert("", "end", values=(key, val))
        tk.Button(win, text="Save", command=save).pack(pady=10)

    def open_theme_selector(self):
        win = tk.Toplevel(self.root)
        win.title("Theme Settings")
        win.geometry("400x160")
        win.configure(bg="#1e1e1e")

        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.theme_manager.add_theme_selector(frame)

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=5)

def launch():
    root = TkinterDnD.Tk() if TkinterDnD else tk.Tk(className="fatx_recovery")
    
    import platform

    
    
if TkinterDnD:
    root = TkinterDnD.Tk() if TkinterDnD else tk.Tk(className="fatx_recovery")
    root.configure(background="#1e1e1e")
    # root = TkinterDnD.Tk() if TkinterDnD else tk.Tk()  # overridden below
    app = FATXGui(root)
    root.drop_target_register(DND_FILES)
    #root.dnd_bind('<<Drop>>', app.drop_handler)
    #root.dnd_bind('<<Drop>>', self.drop_handler)
    root.mainloop()

    def drop_handler(self, event):
        import shlex
        paths = shlex.split(event.data)
        all_files = []
        for path in paths:
            if os.path.isdir(path):
                all_files.extend(self.scanner.find_raw_files(path))
            else:
                all_files.append(path)

        new_count = 0
        dupe_count = 0

        for file in all_files:
            for entry in read_dirents_from_file(file):
                entry_key = get_entry_signature(entry)
                entry_hash = get_entry_hash(entry)
                if entry_hash in self.full_entry_hashes:
                    self.duplicate_counts[entry_hash] += 1
                    logger.debug(f"Exact duplicate (#{self.duplicate_counts[entry_hash]}) {entry['#0']} at cluster {hex(entry['cluster'])}")
                    dupe_count += 1
                    continue
                self.entry_signatures.add(entry_key)
                self.full_entry_hashes.add(entry_hash)
                count = self.duplicate_counts[entry_hash]
                display_name = f"{entry['#0']} (x{count+1})" if count else entry['#0']
                entry["#0"] = display_name
                self.entries.append(entry)
                self.insert_entry(entry)
                new_count += 1

        self.highlight_deleted_entries()
        self.show_duplicate_info(dupe_count)
