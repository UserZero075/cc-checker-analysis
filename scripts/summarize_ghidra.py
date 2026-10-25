#!/usr/bin/env python3
"""Summarize Ghidra counters and fail unless both target binaries were decompiled."""
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
reports = []
for log in sorted(root.glob("*.ghidra.log")):
    text = log.read_text(encoding="utf-8", errors="replace")
    name = log.name.removesuffix(".ghidra.log")
    opened_match = re.search(r"decomp\.openProgram\s*=\s*(true|false)", text, re.I)
    total_match = re.search(r"TOTAL functions seen:\s*(\d+)", text)
    ok_match = re.search(r"Decompiled OK:\s*(\d+)\s*\|\s*Failed:\s*(\d+)\s*\|\s*External:\s*(\d+)", text)
    c_file = root / f"{name}.c"
    fn_file = root / f"{name}.functions.txt"
    exit_file = root / f"{name}.exitcode"
    opened = bool(opened_match and opened_match.group(1).lower() == "true")
    total = int(total_match.group(1)) if total_match else 0
    ok = int(ok_match.group(1)) if ok_match else 0
    failed = int(ok_match.group(2)) if ok_match else 0
    external = int(ok_match.group(3)) if ok_match else 0
    exit_code = exit_file.read_text().strip() if exit_file.exists() else "missing"
    passed = opened and total > 0 and ok > 0 and c_file.exists() and c_file.stat().st_size > 0
    reports.append({"target": name, "open_program": opened, "functions_seen": total,
                    "decompiled_ok": ok, "failed": failed, "external": external,
                    "headless_exit_code": exit_code,
                    "c_bytes": c_file.stat().st_size if c_file.exists() else 0,
                    "function_list_bytes": fn_file.stat().st_size if fn_file.exists() else 0,
                    "passed": passed})

upx_path = root / "upx.status"
upx_status = upx_path.read_text(encoding="utf-8", errors="replace").strip() if upx_path.exists() else "unknown"
main = next((r for r in reports if r["target"].startswith("CCChecker")), None)
dll = next((r for r in reports if r["target"] == "CleanControllerImpl"), None)
complete = bool(upx_status == "unpacked" and main and main["passed"] and dll and dll["passed"])
summary = {"upx_status": upx_status, "targets": reports,
           "complete_for_main_exe_and_dll": complete,
           "limitations": ["Static decompilation only; no target execution or runtime behavior verified."]}
root.mkdir(parents=True, exist_ok=True)
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
sys.exit(0 if complete else 1)
