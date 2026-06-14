"""Skan dvigateli — orkestratsiya mantig'i.

Bu modul CLI va veb interfeys tomonidan birgalikda ishlatiladi.
`progress` callback orqali jonli holat xabarlari uzatiladi (CLI'da print,
vebda log ro'yxatiga qo'shish).
"""
from __future__ import annotations

import datetime
import os
from dataclasses import dataclass

from . import report, runner
from .config import Config
from .model import ScanResult
from .scanners import ScanContext, default_tool_keys, tools_for


@dataclass
class ScanRun:
    """Bitta to'liq skan natijasi."""

    target: str
    target_type: str
    report_dir: str
    html_path: str
    json_path: str
    summary: dict
    findings: list
    results: list


def _noop(_msg: str) -> None:
    pass


def run_scan(target, target_type="fs", tools=None, *, config=None,
             output_dir="reports", pull=True, progress=_noop, mode=None) -> ScanRun:
    """Skanerlarni ishga tushiradi, hisobot yozadi va `ScanRun` qaytaradi.

    Xatolarda `ValueError` yoki `runner.DockerError` ko'taradi.
    """
    config = config or Config()
    if tools is not None:
        config.tools = set(tools)
    if not config.tools:
        config.tools = set(default_tool_keys())
    if mode:
        config.mode = mode

    # Nishonni tekshirish / tayyorlash
    if target_type == "fs":
        # Windows "Copy as path" qo'shtirnoqlarini olib tashlaymiz: "D:\x" -> D:\x
        target = target.strip().strip('"').strip("'")
        if os.path.isdir(target):
            target = os.path.abspath(target)        # konteyner ko'radigan (mount) yo'l
        elif not runner.in_container():
            raise ValueError(f"Papka topilmadi: {target}")
        # Konteyner rejimida ko'rinmaydigan yo'l = xom HOST yo'li (host daemon ulaydi).
    elif target_type == "url":
        target = (target or "").strip().strip('"').strip("'")
        if not target:
            raise ValueError("URL ko'rsatilmadi.")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
    else:  # image
        if not target:
            raise ValueError("Image nomi ko'rsatilmadi.")

    runner.ensure_docker()

    # Hisobot papkasi: <output>/scan-YYYYmmdd-HHMMSS/
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_dir = os.path.join(output_dir, f"scan-{stamp}")
    raw_dir = os.path.join(report_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # Mount rejasi (host yoki konteyner rejimiga qarab)
    out_mount, out_prefix = runner.plan_out_mount(raw_dir)
    src_mount = (None if target_type in ("image", "url")
                 else runner.plan_src_mount(target, read_only=True))
    ctx = ScanContext(target, target_type, raw_dir, config,
                      out_mount, out_prefix, src_mount)
    scanners = tools_for(config.tools, target_type)
    if not scanners:
        raise ValueError(f"'{target_type}' nishon turi uchun hech qanday tool tanlanmadi.")

    offline = config.mode == "offline"
    if offline:
        progress("Offline rejim: bazalar yangilanmaydi, internet talab qiladigan "
                 "toollar o'tkazib yuboriladi.")

    if pull and not offline:
        progress("Skaner image'lari tekshirilmoqda (kerak bo'lsa yuklanadi)...")
        for img in {s.image(ctx) for s in scanners}:
            runner.docker_pull(img)

    results = []
    for scanner in scanners:
        if offline and scanner.offline_support == "no":
            progress(f"[{scanner.key}] offline rejimda o'tkazib yuborildi (internet kerak)")
            results.append(ScanResult(scanner.key, ok=True, skipped=True,
                                      skip_reason="internet kerak (offline rejim)"))
            continue
        progress(f"[{scanner.key}] ishga tushdi ...")
        result = scanner.run(ctx)
        if result.ok:
            progress(f"[{scanner.key}] tugadi - {len(result.findings)} ta "
                     f"({result.duration:.0f}s)")
        else:
            progress(f"[{scanner.key}] XATO - {result.error}")
        results.append(result)

    findings = report.sort_findings([f for r in results for f in r.findings])
    summary = report.summarize(findings)

    json_path = os.path.join(report_dir, "findings.json")
    html_path = os.path.join(report_dir, "report.html")
    report.write_json(json_path, target, target_type, findings, results, summary)
    report.write_html(html_path, target, target_type, findings, results, summary)

    return ScanRun(target, target_type, report_dir, html_path, json_path,
                   summary, findings, results)
