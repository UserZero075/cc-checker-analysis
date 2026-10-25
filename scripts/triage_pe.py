#!/usr/bin/env python3
"""Dependency-free PE metadata, section, import and export inventory."""
import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C4: "arm_thumb"}
DIRECTORIES = {0: "export", 1: "import", 2: "resource", 4: "security", 14: "clr"}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in counts if count)


def analyze(path):
    data = path.read_bytes()
    size = len(data)
    if size < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path.name}: not an MZ PE")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > size or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"{path.name}: invalid PE signature")
    machine, nsec = struct.unpack_from("<HH", data, pe + 4)
    timestamp = struct.unpack_from("<I", data, pe + 8)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"{path.name}: unsupported optional-header magic {magic:#x}")
    is64 = magic == 0x20B
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0]
    size_image = struct.unpack_from("<I", data, opt + 56)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dir_base = opt + (112 if is64 else 96)
    dir_count_off = opt + (108 if is64 else 92)
    dir_count = struct.unpack_from("<I", data, dir_count_off)[0]
    dirs = {}
    for index in range(min(dir_count, 16)):
        rva, length = struct.unpack_from("<II", data, dir_base + index * 8)
        if rva or length:
            dirs[index] = {"address": rva, "size": length}

    sec_base = opt + opt_size
    sections = []
    for i in range(nsec):
        off = sec_base + i * 40
        if off + 40 > size:
            break
        name = data[off:off + 8].split(b"\0", 1)[0].decode("latin-1", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sample = data[raw_ptr:raw_ptr + min(raw_size, 400_000)] if raw_ptr < size else b""
        sections.append({"name": name, "virtual_size": vsize, "rva": vaddr,
                         "raw_size": raw_size, "raw_offset": raw_ptr,
                         "entropy_sample": round(entropy(sample), 4)})

    def rva_offset(rva):
        if rva < struct.unpack_from("<I", data, opt + 60)[0]:
            return rva if rva < size else None
        for section in sections:
            delta = rva - section["rva"]
            if 0 <= delta < section["raw_size"]:
                candidate = section["raw_offset"] + delta
                return candidate if candidate < size else None
        return None

    def cstring(offset, limit=4096):
        if offset is None or offset < 0 or offset >= size:
            return ""
        end = data.find(b"\0", offset, min(size, offset + limit))
        if end < 0:
            end = min(size, offset + limit)
        return data[offset:end].decode("utf-8", "replace")

    imports = []
    if 1 in dirs and dirs[1]["address"]:
        desc = rva_offset(dirs[1]["address"])
        if desc is not None:
            for _ in range(2048):
                if desc + 20 > size:
                    break
                oft, stamp, forward, name_rva, first = struct.unpack_from("<IIIII", data, desc)
                if not (oft or stamp or forward or name_rva or first):
                    break
                module = cstring(rva_offset(name_rva))
                thunk_rva = oft or first
                symbols = []
                thunk_off = rva_offset(thunk_rva)
                width = 8 if is64 else 4
                ordinal_mask = 1 << (width * 8 - 1)
                if thunk_off is not None:
                    for j in range(65536):
                        at = thunk_off + j * width
                        if at + width > size:
                            break
                        value = struct.unpack_from("<Q" if is64 else "<I", data, at)[0]
                        if not value:
                            break
                        if value & ordinal_mask:
                            symbols.append(f"ordinal:{value & 0xffff}")
                        else:
                            name_off = rva_offset(value & (ordinal_mask - 1))
                            symbols.append(cstring(name_off + 2 if name_off is not None else None))
                imports.append({"module": module, "symbols": symbols})
                desc += 20

    exports = []
    if 0 in dirs and dirs[0]["address"]:
        exp_off = rva_offset(dirs[0]["address"])
        if exp_off is not None and exp_off + 40 <= size:
            fields = struct.unpack_from("<IIHHIIIIIII", data, exp_off)
            ordinal_base, nfunc, nname = fields[5], fields[6], fields[7]
            funcs_rva, names_rva, ords_rva = fields[8], fields[9], fields[10]
            funcs_off, names_off, ords_off = map(rva_offset, (funcs_rva, names_rva, ords_rva))
            if funcs_off is not None and names_off is not None and ords_off is not None:
                for i in range(min(nname, 100_000)):
                    name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                    ordinal_index = struct.unpack_from("<H", data, ords_off + i * 2)[0]
                    if ordinal_index >= nfunc:
                        continue
                    function_rva = struct.unpack_from("<I", data, funcs_off + ordinal_index * 4)[0]
                    exports.append({"name": cstring(rva_offset(name_rva)),
                                    "ordinal": ordinal_base + ordinal_index,
                                    "rva": function_rva})

    raw_end = max((s["raw_offset"] + s["raw_size"] for s in sections), default=0)
    entry_section = next((s["name"] for s in sections
                          if s["rva"] <= entry < s["rva"] + max(s["virtual_size"], s["raw_size"])), None)
    return {
        "file": path.name,
        "bytes": size,
        "sha256": sha256(path),
        "format": "PE32+" if is64 else "PE32",
        "machine": f"0x{machine:04x}",
        "architecture": MACHINES.get(machine, "unknown"),
        "timestamp_unix_header": timestamp,
        "image_base": f"0x{image_base:x}",
        "size_of_image": size_image,
        "subsystem": subsystem,
        "entry_rva": f"0x{entry:x}",
        "entry_section": entry_section,
        "section_raw_end": raw_end,
        "overlay_bytes_including_certificate_table": max(0, size - raw_end),
        "directories": {DIRECTORIES.get(i, str(i)): v for i, v in dirs.items()},
        "sections": sections,
        "imports": imports,
        "exports": exports,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    parser.add_argument("--outdir", required=True)
    args = parser.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    failed = False
    for arg in args.files:
        path = Path(arg)
        try:
            result = analyze(path)
            out = outdir / f"{path.name}.triage.json"
            out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(json.dumps({"file": path.name, "sha256": result["sha256"],
                              "bytes": result["bytes"], "format": result["format"],
                              "architecture": result["architecture"],
                              "entry_section": result["entry_section"],
                              "imports": len(result["imports"]), "exports": len(result["exports"]),
                              "report": str(out)}, ensure_ascii=False))
        except Exception as exc:
            failed = True
            print(json.dumps({"file": path.name, "error": str(exc)}, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
