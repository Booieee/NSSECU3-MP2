#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Stdlib-only Forensic File Scanner (Windows)

Fixes requested:
1) More accurate mounted volume listing (includes folder mount points) using:
   - FindFirstVolumeW / FindNextVolumeW
   - GetVolumePathNamesForVolumeNameW
2) Progress printed every 10 scans (overall encountered + targets processed)
3) Scan path selection via File Explorer (tkinter askdirectory)

Core requirements:
- Recursively scan user-selected mounted path
- Identify targets by filename stem pattern File001..File220 (ignores extension)
- Read raw bytes, detect file type via data-driven magic-number signature table
- For each target: first 50 bytes hex, SHA-256, metadata (path/name/size)
- Graceful error handling (log errors, continue)
- Validate expected 220 processed targets (warn if != 220)
- Write CSV output and print grouped counts by detected type
- No modifications to mounted volume
"""

import argparse
import csv
import ctypes
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ----------------------------
# Signature table (data-driven)
# ----------------------------

@dataclass(frozen=True)
class SignatureRule:
    rule_name: str
    detected_type: str
    offset: int
    magic: bytes

SIGNATURE_RULES: List[SignatureRule] = [
    # Executables / binaries
    SignatureRule("pe_mz", "EXE/DLL (PE)", 0, b"MZ"),
    SignatureRule("elf", "ELF", 0, b"\x7fELF"),

    # Documents
    SignatureRule("pdf", "PDF", 0, b"%PDF-"),
    SignatureRule("ole_cf", "MS Office (OLE/CF)", 0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"),

    # Archives
    SignatureRule("zip_pk0304", "ZIP", 0, b"PK\x03\x04"),
    SignatureRule("zip_pk0506", "ZIP (empty)", 0, b"PK\x05\x06"),
    SignatureRule("zip_pk0708", "ZIP (spanned)", 0, b"PK\x07\x08"),
    SignatureRule("rar_v4", "RAR", 0, b"Rar!\x1A\x07\x00"),
    SignatureRule("rar_v5", "RAR", 0, b"Rar!\x1A\x07\x01\x00"),
    SignatureRule("7z", "7-Zip", 0, b"7z\xBC\xAF\x27\x1C"),
    SignatureRule("gzip", "GZIP", 0, b"\x1F\x8B"),
    SignatureRule("bz2", "BZIP2", 0, b"BZh"),

    # Images
    SignatureRule("png", "PNG", 0, b"\x89PNG\r\n\x1a\n"),
    SignatureRule("jpg", "JPEG", 0, b"\xFF\xD8\xFF"),
    SignatureRule("gif87a", "GIF", 0, b"GIF87a"),
    SignatureRule("gif89a", "GIF", 0, b"GIF89a"),
    SignatureRule("bmp", "BMP", 0, b"BM"),
    SignatureRule("tiff_le", "TIFF", 0, b"II*\x00"),
    SignatureRule("tiff_be", "TIFF", 0, b"MM\x00*"),

    # Audio/video
    SignatureRule("mp3_id3", "MP3", 0, b"ID3"),
    SignatureRule("wav_riff", "WAV/RIFF", 0, b"RIFF"),

    # DB
    SignatureRule("sqlite3", "SQLite", 0, b"SQLite format 3\x00"),

    # MP4 family: 'ftyp' at offset 4
    SignatureRule("mp4_ftyp", "MP4/MOV", 4, b"ftyp"),
]

def _max_sig_read(rules: List[SignatureRule]) -> int:
    if not rules:
        return 64
    span = max(r.offset + len(r.magic) for r in rules)
    return max(64, span)

MAX_SIG_READ = _max_sig_read(SIGNATURE_RULES)

def detect_signature(header: bytes, rules: List[SignatureRule]) -> Tuple[str, str]:
    for r in rules:
        end = r.offset + len(r.magic)
        if len(header) >= end and header[r.offset:end] == r.magic:
            return r.detected_type, r.rule_name
    return "UNKNOWN", ""


# ----------------------------
# Target detection: File001..File220 (ignore extension)
# ----------------------------

TARGET_NAME_RE = re.compile(r"^file(\d{3})$", re.IGNORECASE)

def is_target_filename(p: Path) -> bool:
    m = TARGET_NAME_RE.match(p.stem)  # ignore extension
    if not m:
        return False
    n = int(m.group(1))
    return 1 <= n <= 220


# ----------------------------
# File utilities
# ----------------------------

def read_first_bytes(path: Path, n: int) -> bytes:
    with path.open("rb") as f:
        return f.read(n)

def sha256_file(path: Path, first_already_read: Optional[bytes] = None) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        if first_already_read is not None:
            h.update(first_already_read)
            f.seek(len(first_already_read), os.SEEK_SET)

        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ----------------------------
# Recursive enumeration
# ----------------------------

def iter_files_recursive(root: Path) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in filenames:
            yield Path(dirpath) / name


# ----------------------------
# Windows volume listing (accurate)
# ----------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

FindFirstVolumeW = kernel32.FindFirstVolumeW
FindFirstVolumeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
FindFirstVolumeW.restype = ctypes.c_void_p

FindNextVolumeW = kernel32.FindNextVolumeW
FindNextVolumeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
FindNextVolumeW.restype = ctypes.c_int

FindVolumeClose = kernel32.FindVolumeClose
FindVolumeClose.argtypes = [ctypes.c_void_p]
FindVolumeClose.restype = ctypes.c_int

GetVolumePathNamesForVolumeNameW = kernel32.GetVolumePathNamesForVolumeNameW
GetVolumePathNamesForVolumeNameW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_wchar_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]
GetVolumePathNamesForVolumeNameW.restype = ctypes.c_int

GetVolumeInformationW = kernel32.GetVolumeInformationW
GetVolumeInformationW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_wchar_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_wchar_p, ctypes.c_uint32
]
GetVolumeInformationW.restype = ctypes.c_int

def _get_volume_paths(volume_name: str) -> List[str]:
    # First call to get required length
    needed = ctypes.c_uint32(0)
    GetVolumePathNamesForVolumeNameW(volume_name, None, 0, ctypes.byref(needed))
    if needed.value == 0:
        return []

    buf = ctypes.create_unicode_buffer(needed.value)
    ok = GetVolumePathNamesForVolumeNameW(volume_name, buf, needed.value, ctypes.byref(needed))
    if not ok:
        return []

    # MULTI_SZ (null-separated strings ending with double-null)
    raw = buf[:]
    parts = [s for s in raw.split("\x00") if s]
    return parts

def list_mounted_volumes() -> List[Dict[str, str]]:
    """
    Returns list of volumes with:
    - volume_name: \\?\Volume{GUID}\
    - mount_points: e.g. C:\ or C:\Mount\Image\
    - label, filesystem, serial_hex
    """
    results: List[Dict[str, str]] = []
    buf = ctypes.create_unicode_buffer(1024)

    h = FindFirstVolumeW(buf, len(buf))
    if not h or h == ctypes.c_void_p(-1).value:
        return results

    try:
        while True:
            volume_name = buf.value  # \\?\Volume{...}\

            mount_points = _get_volume_paths(volume_name)
            # Query volume info using a mount point if available (more reliable)
            query_path = mount_points[0] if mount_points else volume_name

            vol_name_buf = ctypes.create_unicode_buffer(261)
            fs_name_buf = ctypes.create_unicode_buffer(261)
            serial = ctypes.c_uint32(0)
            max_comp = ctypes.c_uint32(0)
            fs_flags = ctypes.c_uint32(0)

            ok = GetVolumeInformationW(
                query_path,
                vol_name_buf, ctypes.sizeof(vol_name_buf) // ctypes.sizeof(ctypes.c_wchar),
                ctypes.byref(serial),
                ctypes.byref(max_comp),
                ctypes.byref(fs_flags),
                fs_name_buf, ctypes.sizeof(fs_name_buf) // ctypes.sizeof(ctypes.c_wchar),
            )

            results.append({
                "volume_name": volume_name,
                "mount_points": ", ".join(mount_points) if mount_points else "",
                "label": vol_name_buf.value if ok else "",
                "filesystem": fs_name_buf.value if ok else "",
                "serial_hex": f"{serial.value:08X}" if ok else "",
            })

            ok_next = FindNextVolumeW(h, buf, len(buf))
            if not ok_next:
                break
    finally:
        FindVolumeClose(h)

    return results


# ----------------------------
# CSV writing
# ----------------------------

CSV_COLUMNS = [
    "file_path",
    "file_name",
    "file_size",
    "sha256",
    "first_50_bytes_hex",
    "detected_type",
    "signature_match",
]

def write_csv(out_path: Path, rows: List[Dict[str, str]]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)


# ----------------------------
# File Explorer selection (stdlib tkinter)
# ----------------------------

def pick_scan_path_via_explorer() -> Path:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except Exception:
        raise RuntimeError("tkinter is not available in this Python install. Use --path instead.")

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    messagebox.showinfo("Select Scan Folder", "Select the mounted drive/folder to scan (read-only).")
    folder = filedialog.askdirectory(title="Select mounted drive/folder to scan")
    root.destroy()

    if not folder:
        raise RuntimeError("No folder selected.")
    return Path(folder)


# ----------------------------
# Scanner core
# ----------------------------

def scan(scan_root: Path, out_csv: Path) -> int:
    # Print mounted volumes (includes folder mount points)
    volumes = list_mounted_volumes()
    print("Mounted volumes (GUID + mount points):")
    if not volumes:
        print("  (No volumes returned by API; still continuing.)")
    else:
        for v in volumes:
            mp = f" mounts=[{v['mount_points']}]" if v["mount_points"] else " mounts=[]"
            label = f" label={v['label']}" if v["label"] else ""
            fs = f" fs={v['filesystem']}" if v["filesystem"] else ""
            serial = f" serial={v['serial_hex']}" if v["serial_hex"] else ""
            print(f"  - {v['volume_name']}{mp}{label}{fs}{serial}")

    print("\nTarget scan path:")
    print(f"  {scan_root}\n")

    total_files_encountered = 0
    target_matched_by_name = 0
    targets_known_sig = 0
    targets_ok = 0
    targets_err = 0

    type_counter = Counter()
    errors: List[Tuple[str, str]] = []
    rows: List[Dict[str, str]] = []

    t0 = time.time()

    for p in iter_files_recursive(scan_root):
        total_files_encountered += 1

        # Progress every 10 overall files encountered (what users typically mean by “per 10 scans”)
        if total_files_encountered % 10 == 0:
            print(f"[progress] overall_files_encountered={total_files_encountered}  latest={p}")

        # Only process targets matching File### stem
        if not is_target_filename(p):
            continue

        target_matched_by_name += 1

        try:
            st = p.stat()
            header = read_first_bytes(p, max(MAX_SIG_READ, 50))
            first50_hex = header[:50].hex().upper()
            detected_type, sig_name = detect_signature(header, SIGNATURE_RULES)
            if detected_type != "UNKNOWN":
                targets_known_sig += 1

            sha = sha256_file(p, first_already_read=header)

            rows.append({
                "file_path": str(p),
                "file_name": p.name,
                "file_size": str(st.st_size),
                "sha256": sha,
                "first_50_bytes_hex": first50_hex,
                "detected_type": detected_type,
                "signature_match": sig_name,
            })

            targets_ok += 1
            type_counter[detected_type] += 1

        except Exception as e:
            targets_err += 1
            errors.append((str(p), repr(e)))

            rows.append({
                "file_path": str(p),
                "file_name": p.name,
                "file_size": "",
                "sha256": "",
                "first_50_bytes_hex": "",
                "detected_type": "UNREADABLE/ERROR",
                "signature_match": "",
            })
            type_counter["UNREADABLE/ERROR"] += 1

        # Progress every 10 TARGET files processed (also included so it can’t “miss”)
        processed_targets = targets_ok + targets_err
        if processed_targets % 10 == 0:
            print(f"[progress] target_files_processed={processed_targets}  latest_target={p}")

    # Prevent writing output into scan_root (mounted volume)
    try:
        sr = scan_root.resolve()
        oc = out_csv.resolve()
        if str(oc).lower().startswith(str(sr).lower()):
            print("\nWARNING: Output CSV path is inside scan root (mounted volume).")
            print("         Writing CSV to current working directory to keep read-only operation.")
            out_csv = Path.cwd() / out_csv.name
    except Exception:
        pass

    write_csv(out_csv, rows)

    elapsed = time.time() - t0

    print("\nScan summary:")
    print(f"  Total files encountered (overall): {total_files_encountered}")
    print(f"  Total files matching target name pattern (File001..File220 stem): {target_matched_by_name}")
    print(f"  Total target files matching known signatures: {targets_known_sig}")
    print(f"  Total target files successfully scanned: {targets_ok}")
    print(f"  Total unreadable target files / errors: {targets_err}")
    print(f"  Output CSV: {out_csv}")
    print(f"  Elapsed seconds: {elapsed:.2f}")

    print("\nGrouped count by detected file type (targets):")
    for k in sorted(type_counter):
        print(f"  - {k}: {type_counter[k]}")

    scanned_total = targets_ok + targets_err
    if scanned_total != 220:
        print(f"\nWARNING: Expected 220, Scanned {scanned_total} (targets processed). Output was still written.")
    else:
        print(f"\nValidation: Expected 220, Scanned {scanned_total}")

    if errors:
        print("\nErrors (first 50):")
        for path_str, err in errors[:50]:
            print(f"  - {path_str} -> {err}")
        if len(errors) > 50:
            print(f"  ... ({len(errors) - 50} more)")

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Stdlib-only forensic scanner for mounted disk images (Windows).")
    ap.add_argument("--path", help="Root path to scan. If omitted, opens File Explorer folder picker.")
    ap.add_argument("--out", default="scan_results.csv", help="Output CSV path (default: scan_results.csv).")
    args = ap.parse_args()

    scan_root = Path(args.path.strip('"')) if args.path else pick_scan_path_via_explorer()
    if not scan_root.exists():
        print(f"ERROR: Scan path does not exist: {scan_root}", file=sys.stderr)
        return 2

    out_csv = Path(args.out.strip('"'))
    return scan(scan_root=scan_root, out_csv=out_csv)


if __name__ == "__main__":
    raise SystemExit(main())