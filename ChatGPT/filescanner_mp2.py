#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Forensic File Scanner (Windows, stdlib-only)

- Lists mounted drives/volumes
- Recursively scans a user-selected path (read-only)
- Locates dataset targets by filename pattern File001..File220 (ignores extension)
- Detects file type by magic-number signatures (data-driven signature table)
- For each target: first 50 bytes hex + SHA-256 + metadata
- Progress every 10 target files processed
- Validates expected 220 targets (warns if not)
- Writes results to CSV and prints console summary grouped by detected type
"""

import argparse
import csv
import ctypes
import os
import re
import sys
import time
from collections import Counter, defaultdict
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

# NOTE: Keep this table centralized (no scattered hard-coded checks).
# Add/remove signatures here as needed for your dataset.
SIGNATURE_RULES: List[SignatureRule] = [
    # Executables / binaries
    SignatureRule("pe_mz", "EXE/DLL (PE)", 0, b"MZ"),
    SignatureRule("elf", "ELF", 0, b"\x7fELF"),

    # Documents
    SignatureRule("pdf", "PDF", 0, b"%PDF-"),
    SignatureRule("ole_cf", "MS Office (OLE/CF)", 0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"),

    # Archives / compressed
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

    # Audio/video (simple header checks)
    SignatureRule("mp3_id3", "MP3", 0, b"ID3"),
    SignatureRule("wav_riff", "WAV/RIFF", 0, b"RIFF"),

    # Databases
    SignatureRule("sqlite3", "SQLite", 0, b"SQLite format 3\x00"),

    # MP4 family: 'ftyp' at offset 4
    SignatureRule("mp4_ftyp", "MP4/MOV", 4, b"ftyp"),
]

def max_signature_span(rules: List[SignatureRule]) -> int:
    """How many bytes we must read from the header to test all rules."""
    if not rules:
        return 0
    return max(r.offset + len(r.magic) for r in rules)

MAX_SIG_READ = max(64, max_signature_span(SIGNATURE_RULES))  # read at least 64 bytes


# ----------------------------
# Windows drive/volume listing
# ----------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GetLogicalDriveStringsW = kernel32.GetLogicalDriveStringsW
GetLogicalDriveStringsW.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]
GetLogicalDriveStringsW.restype = ctypes.c_uint32

GetDriveTypeW = kernel32.GetDriveTypeW
GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
GetDriveTypeW.restype = ctypes.c_uint32

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

DRIVE_TYPE_MAP = {
    0: "UNKNOWN",
    1: "NO_ROOT_DIR",
    2: "REMOVABLE",
    3: "FIXED",
    4: "REMOTE",
    5: "CDROM",
    6: "RAMDISK",
}

def list_mounted_drives() -> List[Dict[str, str]]:
    """Return a list of drive info dicts for mounted volumes."""
    buf_len = 512
    while True:
        buf = ctypes.create_unicode_buffer(buf_len)
        needed = GetLogicalDriveStringsW(buf_len, buf)
        if needed == 0:
            raise OSError("GetLogicalDriveStringsW failed")
        if needed < buf_len:
            break
        buf_len = needed + 1

    drives = [d for d in buf.value.split("\x00") if d]
    results: List[Dict[str, str]] = []

    for d in drives:
        dtype = DRIVE_TYPE_MAP.get(GetDriveTypeW(d), "UNKNOWN")
        vol_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_uint32(0)
        max_comp = ctypes.c_uint32(0)
        fs_flags = ctypes.c_uint32(0)

        ok = GetVolumeInformationW(
            d,
            vol_name_buf, ctypes.sizeof(vol_name_buf) // ctypes.sizeof(ctypes.c_wchar),
            ctypes.byref(serial),
            ctypes.byref(max_comp),
            ctypes.byref(fs_flags),
            fs_name_buf, ctypes.sizeof(fs_name_buf) // ctypes.sizeof(ctypes.c_wchar),
        )

        results.append({
            "drive": d,
            "type": dtype,
            "label": vol_name_buf.value if ok else "",
            "filesystem": fs_name_buf.value if ok else "",
            "serial_hex": f"{serial.value:08X}" if ok else "",
        })

    return results


# ----------------------------
# Target detection (File001..File220)
# ----------------------------

# Matches File001..File220 ignoring extension (e.g., File007, File007.bin, FILE120.tmp)
TARGET_NAME_RE = re.compile(r"^file(\d{3})$", re.IGNORECASE)

def is_target_filename(path: Path) -> bool:
    """True if basename (without extension) matches File001..File220."""
    stem = path.stem  # ignores extension
    m = TARGET_NAME_RE.match(stem)
    if not m:
        return False
    n = int(m.group(1))
    return 1 <= n <= 220


# ----------------------------
# Signature detection
# ----------------------------

def detect_signature(header: bytes, rules: List[SignatureRule]) -> Tuple[str, str]:
    """
    Returns (detected_type, rule_name). If no match, returns ("UNKNOWN", "").
    """
    for r in rules:
        end = r.offset + len(r.magic)
        if len(header) >= end and header[r.offset:end] == r.magic:
            return r.detected_type, r.rule_name
    return "UNKNOWN", ""


# ----------------------------
# File reading utilities
# ----------------------------

def read_first_bytes(path: Path, n: int) -> bytes:
    with path.open("rb") as f:
        return f.read(n)

def sha256_file(path: Path, first_already_read: Optional[bytes] = None) -> str:
    """
    Compute SHA-256 with streaming reads.
    If first_already_read is provided, it is included in hash and the file is read from its current position.
    """
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as f:
        if first_already_read is not None:
            h.update(first_already_read)
        else:
            # Read from start if nothing pre-read
            pass

        # If we pre-read some bytes, advance file pointer accordingly
        if first_already_read is not None:
            f.seek(len(first_already_read), os.SEEK_SET)

        while True:
            chunk = f.read(1024 * 1024)  # 1MB
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ----------------------------
# Recursive enumeration
# ----------------------------

def iter_files_recursive(root: Path) -> Iterable[Path]:
    """
    Yields all regular files under root (recursive), skipping reparse points where possible.
    Uses os.walk for performance on Windows.
    """
    # followlinks=False avoids traversing junctions/symlinks
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Optionally prune directories you know you can't access (left generic here)
        for name in filenames:
            p = Path(dirpath) / name
            yield p


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
        for r in rows:
            w.writerow(r)


# ----------------------------
# Scanner core
# ----------------------------

def scan(root: Path, out_csv: Path) -> int:
    drives = list_mounted_drives()
    print("Mounted drives/volumes:")
    for info in drives:
        label = f" ({info['label']})" if info["label"] else ""
        fs = f" [{info['filesystem']}]" if info["filesystem"] else ""
        serial = f" serial={info['serial_hex']}" if info["serial_hex"] else ""
        print(f"  - {info['drive']}  type={info['type']}{label}{fs}{serial}")

    print("\nTarget scan path:")
    print(f"  {root}")
    print("")

    total_files_encountered = 0
    total_targets_found = 0
    total_targets_scanned_ok = 0
    total_targets_errors = 0

    # “matching known signatures” is counted among targets attempted
    total_targets_known_sig = 0

    type_counter = Counter()
    error_list: List[Tuple[str, str]] = []  # (path, error)
    rows: List[Dict[str, str]] = []

    t0 = time.time()

    for p in iter_files_recursive(root):
        total_files_encountered += 1

        # Only attempt dataset targets by filename pattern (File001..File220)
        if not is_target_filename(p):
            continue

        total_targets_found += 1

        # Process the target file (read-only)
        try:
            st = p.stat()
            file_size = str(st.st_size)

            # Read enough header bytes to test all signatures + also keep first 50
            header = read_first_bytes(p, max(MAX_SIG_READ, 50))
            first50 = header[:50]
            first50_hex = first50.hex().upper()

            detected_type, sig_name = detect_signature(header, SIGNATURE_RULES)
            if detected_type != "UNKNOWN":
                total_targets_known_sig += 1

            # SHA256 (include what we already read to avoid re-reading those bytes twice)
            sha = sha256_file(p, first_already_read=header)

            rows.append({
                "file_path": str(p),
                "file_name": p.name,
                "file_size": file_size,
                "sha256": sha,
                "first_50_bytes_hex": first50_hex,
                "detected_type": detected_type,
                "signature_match": sig_name,
            })

            total_targets_scanned_ok += 1
            type_counter[detected_type] += 1

        except Exception as e:
            total_targets_errors += 1
            error_list.append((str(p), repr(e)))

            # Still write an output row (as required: warn but still write output)
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

        # Progress every 10 target files processed (success or error)
        processed = total_targets_scanned_ok + total_targets_errors
        if processed % 10 == 0:
            print(f"[progress] processed_targets={processed}  latest={p}")

    # Write CSV
    write_csv(out_csv, rows)

    dt = time.time() - t0

    # Console summary
    print("\nScan summary:")
    print(f"  Total files encountered (overall): {total_files_encountered}")
    print(f"  Total target files matched (File001..File220 name pattern): {total_targets_found}")
    print(f"  Total target files matching known signatures: {total_targets_known_sig}")
    print(f"  Total target files successfully scanned: {total_targets_scanned_ok}")
    print(f"  Total unreadable target files / errors: {total_targets_errors}")
    print(f"  Output CSV: {out_csv}")
    print(f"  Elapsed seconds: {dt:.2f}")

    print("\nGrouped count by detected file type (targets):")
    if type_counter:
        for k in sorted(type_counter.keys()):
            print(f"  - {k}: {type_counter[k]}")
    else:
        print("  (none)")

    # Validation (expected exactly 220 target files scanned)
    scanned_total = total_targets_scanned_ok + total_targets_errors
    if scanned_total != 220:
        print(f"\nWARNING: Expected 220, Scanned {scanned_total} (targets processed). Output was still written.")
    else:
        print(f"\nValidation: Expected 220, Scanned {scanned_total}")

    # Print errors (paths) at end for forensic traceability
    if error_list:
        print("\nErrors (unreadable targets):")
        for path_str, err in error_list[:50]:
            print(f"  - {path_str}  -> {err}")
        if len(error_list) > 50:
            print(f"  ... ({len(error_list) - 50} more)")

    return 0


# ----------------------------
# CLI / interactive selection
# ----------------------------

def prompt_for_path(drives: List[Dict[str, str]]) -> Path:
    """
    Simple interactive prompt:
    - shows drives
    - user can type a full path or choose a drive letter index
    """
    print("\nSelect a scan path.")
    print("You can:")
    print("  - Type a full path (e.g., E:\\ or E:\\MountedImage)")
    print("  - Or choose a drive number from the list below\n")

    for i, info in enumerate(drives, start=1):
        label = f" ({info['label']})" if info["label"] else ""
        print(f"  {i}. {info['drive']}{label} [{info['type']}]")

    choice = input("\nEnter choice (number) or full path: ").strip().strip('"')
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(drives):
            return Path(drives[idx - 1]["drive"])
        print("Invalid drive number; defaulting to C:\\")
        return Path("C:\\")
    else:
        return Path(choice)

def main() -> int:
    ap = argparse.ArgumentParser(description="Stdlib-only forensic scanner for mounted disk images (Windows).")
    ap.add_argument("--path", help="Root path to scan (e.g., E:\\MountedImage). If omitted, prompts interactively.")
    ap.add_argument("--out", default="scan_results.csv", help="Output CSV filename/path (default: scan_results.csv).")
    args = ap.parse_args()

    drives = list_mounted_drives()

    if args.path:
        root = Path(args.path.strip().strip('"'))
    else:
        root = prompt_for_path(drives)

    if not root.exists():
        print(f"ERROR: Scan path does not exist: {root}", file=sys.stderr)
        return 2

    out_csv = Path(args.out.strip().strip('"'))

    # Ensure we don't accidentally write into the mounted volume:
    # - output defaults to current working directory unless user specifies otherwise.
    # - still allowed even if user points it to mounted volume, but that would violate “no modifications”.
    #   We guard against that by warning and redirecting to CWD.
    try:
        root_resolved = root.resolve()
        out_resolved = out_csv.resolve()
        if str(out_resolved).lower().startswith(str(root_resolved).lower()):
            print("WARNING: Output CSV path is inside the scan root (mounted volume).")
            print("         To preserve read-only operation, writing CSV to current directory instead.")
            out_csv = Path.cwd() / out_csv.name
    except Exception:
        # If resolve fails (permissions), just proceed; user should keep --out outside the mounted drive.
        pass

    return scan(root=root, out_csv=out_csv)

if __name__ == "__main__":
    raise SystemExit(main())