"""SecScan CLI — buyruq qatori interfeysi va orkestratsiya.

Foydalanish:
    python run.py scan <papka|image> [tanlovlar]
    python run.py serve           # veb interfeysni ishga tushiradi
    python run.py pull            # skaner image'larini oldindan yuklab oladi
    python run.py version
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, engine, report, runner
from .config import Config, load_dotenv
from .scanners import TOOLS


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Tayyor skanerlar (Trivy, Gitleaks, Semgrep) bilan loyihani "
                    "xavfsizlik tomondan tekshiradi va hisobot beradi.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="papka, Docker image yoki URL ni skanlash")
    sp.add_argument("target", help="papka yo'li, image nomi yoki URL")
    sp.add_argument("--type", choices=["fs", "image", "url"], default="fs",
                    help="nishon turi: fs = papka/kod (standart), image = Docker image, url = DAST")
    sp.add_argument("--tools", default="",
                    help="vergul bilan tool kalitlari (standart: hammasi). Mavjud: "
                         + ", ".join(c.key for c in TOOLS))
    sp.add_argument("--output", default="reports",
                    help="hisobotlar saqlanadigan papka (standart: reports)")
    sp.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"],
                    help="shu daraja+ topilsa, chiqish kodi != 0 (CI gate uchun)")
    sp.add_argument("--no-pull", action="store_true",
                    help="image'larni avtomatik yuklab olmaslik")
    sp.add_argument("--open", action="store_true",
                    help="tugagach HTML hisobotni brauzerda ochish")

    sv = sub.add_parser("serve", help="veb interfeysni ishga tushirish (FastAPI)")
    sv.add_argument("--host", default="127.0.0.1",
                    help="tinglash manzili (LAN uchun 0.0.0.0)")
    sv.add_argument("--port", type=int, default=8000, help="port (standart: 8000)")

    sub.add_parser("pull", help="barcha skaner image'larini yuklab olish")
    sub.add_parser("version", help="versiyani ko'rsatish")
    return p


def _parse_tools(raw: str) -> set:
    valid = {c.key for c in TOOLS}
    tools = {t.strip().lower() for t in raw.split(",") if t.strip()}
    invalid = tools - valid
    if invalid:
        raise SystemExit(f"Noma'lum tool: {', '.join(sorted(invalid))}. "
                         f"Mavjud: {', '.join(sorted(valid))}")
    return tools


def _cmd_pull(config: Config) -> int:
    runner.ensure_docker()
    images = [config.trivy_image, config.gitleaks_image, config.semgrep_image,
              config.grype_image, config.osv_image, config.trufflehog_image,
              config.bandit_image, config.hadolint_image, config.checkov_image,
              config.dockle_image, config.nuclei_image]
    rc = 0
    for img in images:
        print(f"-> {img} yuklanmoqda ...")
        proc = runner.docker_pull(img)
        if proc.returncode != 0:
            rc = 1
            print(f"   XATO: {(proc.stderr or '').strip()}")
        else:
            print("   tayyor")
    return rc


def _cmd_scan(args, config: Config) -> int:
    if args.tools:
        config.tools = _parse_tools(args.tools)
    if args.fail_on:
        config.fail_on = args.fail_on

    try:
        run = engine.run_scan(
            args.target, args.type, config.tools or None,
            config=config, output_dir=args.output,
            pull=not args.no_pull, progress=print,
        )
    except ValueError as exc:
        raise SystemExit(str(exc))

    report.print_console(run.target, run.findings, run.results, run.summary)
    print(f"  HTML hisobot : {run.html_path}")
    print(f"  JSON hisobot : {run.json_path}\n")

    if args.open:
        import webbrowser
        webbrowser.open(os.path.abspath(run.html_path))

    # CI gate: fail_on darajasiga ko'ra chiqish kodi
    if report.meets_threshold(run.findings, config.fail_on):
        print(f"  '{config.fail_on}' yoki undan yuqori daraja topildi "
              f"-> chiqish kodi 2")
        return 2
    return 0


def _cmd_serve(args) -> int:
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        raise SystemExit(
            "FastAPI/uvicorn o'rnatilmagan. Quyidagini bajaring:\n"
            "    pip install -r requirements.txt"
        )
    from .web import create_app

    print("=" * 56)
    print("  SecScan veb interfeysi ishga tushdi")
    print(f"  Manzil : http://{args.host}:{args.port}")
    print(f"  API doc: http://{args.host}:{args.port}/docs")
    print("  To'xtatish: Ctrl+C")
    print("=" * 56)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv=None) -> int:
    # Windows konsolida UTF-8 chiqishini ta'minlaymiz (belgilar buzilmasligi uchun)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    argv = sys.argv[1:] if argv is None else argv
    # Joriy papkadagi .env ni yuklaymiz (image versiyalari va h.k.)
    load_dotenv(os.path.join(os.getcwd(), ".env"))
    config = Config()

    args = _build_parser().parse_args(argv)

    try:
        if args.cmd == "version":
            print(f"SecScan {__version__}")
            return 0
        if args.cmd == "pull":
            return _cmd_pull(config)
        if args.cmd == "scan":
            return _cmd_scan(args, config)
        if args.cmd == "serve":
            return _cmd_serve(args)
    except runner.DockerError as exc:
        print(f"\n[Docker xatosi] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nBekor qilindi.", file=sys.stderr)
        return 130
    return 0
