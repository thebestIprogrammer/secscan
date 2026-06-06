"""Hisobot — konsol xulosasi, JSON va HTML.

Barcha skanerlarning `Finding`'lari shu yerda jamlanadi va uch ko'rinishda
saqlanadi: konsolda qisqa xulosa, `findings.json` (mashina uchun), `report.html`
(odam uchun).
"""
from __future__ import annotations

import datetime
import html
import json
import os

from .model import CATEGORY_LABELS, SEVERITY_ORDER, Severity

# Har bir daraja uchun rang (HTML badge'lari uchun).
SEVERITY_COLORS = {
    "CRITICAL": "#7b1fa2",
    "HIGH": "#c62828",
    "MEDIUM": "#ef6c00",
    "LOW": "#f9a825",
    "INFO": "#0277bd",
    "UNKNOWN": "#607d8b",
}


def summarize(findings):
    """Daraja, toifa va skaner bo'yicha sanaydi."""
    by_sev = {s.label: 0 for s in SEVERITY_ORDER}
    by_cat = {}
    by_scanner = {}
    for f in findings:
        by_sev[f.severity.label] = by_sev.get(f.severity.label, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
    return {"by_severity": by_sev, "by_category": by_cat,
            "by_scanner": by_scanner, "total": len(findings)}


def sort_findings(findings):
    """Xavfli darajadan kamiga, keyin toifa bo'yicha tartiblaydi."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (rank.get(f.severity, 99), f.category, f.file))


def meets_threshold(findings, fail_on: str) -> bool:
    """`fail_on` darajasi yoki undan yuqorisi mavjudligini aniqlaydi (CI gate uchun)."""
    if not fail_on or fail_on == "none":
        return False
    threshold = Severity.parse(fail_on)
    return any(f.severity >= threshold for f in findings)


# ---------------------------------------------------------------- konsol

def print_console(target, findings, results, summary):
    line = "=" * 60
    print("\n" + line)
    print("  SecScan - xavfsizlik tekshiruvi xulosasi")
    print(line)
    print(f"  Nishon : {target}")
    print(f"  Jami   : {summary['total']} ta kamchilik\n")

    print("  Daraja bo'yicha:")
    for s in SEVERITY_ORDER:
        count = summary["by_severity"].get(s.label, 0)
        if count:
            print(f"    {s.label:<9} {count}")

    if summary["by_category"]:
        print("\n  Toifa bo'yicha:")
        for cat, count in summary["by_category"].items():
            print(f"    {CATEGORY_LABELS.get(cat, cat):<18} {count}")

    print("\n  Skanerlar:")
    for r in results:
        if r.skipped:
            status = f"o'tkazib yuborildi ({r.skip_reason})"
        elif r.ok:
            status = f"OK - {len(r.findings)} ta topildi  ({r.duration:.0f}s)"
        else:
            status = f"XATO - {r.error}"
        print(f"    {r.scanner:<10} {status}")
    print(line + "\n")


# ---------------------------------------------------------------- JSON

def write_json(path, target, target_type, findings, results, summary):
    payload = {
        "target": target,
        "target_type": target_type,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "scanners": [
            {"scanner": r.scanner, "ok": r.ok, "skipped": r.skipped,
             "skip_reason": r.skip_reason, "error": r.error,
             "duration_sec": round(r.duration, 1), "findings": len(r.findings)}
            for r in results
        ],
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- HTML

def _badge(severity: Severity) -> str:
    color = SEVERITY_COLORS.get(severity.label, "#607d8b")
    return f'<span class="badge" style="background:{color}">{severity.label}</span>'


def _esc(text) -> str:
    return html.escape(str(text or ""))


def _summary_cards(summary) -> str:
    cards = []
    for s in SEVERITY_ORDER:
        count = summary["by_severity"].get(s.label, 0)
        color = SEVERITY_COLORS[s.label]
        dim = "" if count else ' style="opacity:.35"'
        cards.append(
            f'<div class="card"{dim}><div class="num" style="color:{color}">{count}</div>'
            f'<div class="lbl">{s.label}</div></div>'
        )
    return "".join(cards)


def _scanner_rows(results) -> str:
    rows = []
    for r in results:
        if r.skipped:
            state = f'<span class="muted">o\'tkazib yuborildi — {_esc(r.skip_reason)}</span>'
        elif r.ok:
            state = f'<span class="ok">OK</span> · {len(r.findings)} ta · {r.duration:.0f}s'
        else:
            state = f'<span class="err">XATO</span> · {_esc(r.error)}'
        rows.append(f"<tr><td><b>{_esc(r.scanner)}</b></td><td>{state}</td></tr>")
    return "".join(rows)


def _finding_rows(findings) -> str:
    if not findings:
        return ('<tr><td colspan="6" class="clean">Hech qanday kamchilik '
                'topilmadi 🎉</td></tr>')
    rows = []
    for f in findings:
        ident = _esc(f.identifier)
        if f.reference:
            ident = f'<a href="{_esc(f.reference)}" target="_blank" rel="noopener">{ident}</a>'
        desc = f'<div class="desc">{_esc(f.description)}</div>' if f.description else ""
        rem = f'<div class="rem">↳ {_esc(f.remediation)}</div>' if f.remediation else ""
        rows.append(
            "<tr>"
            f"<td>{_badge(f.severity)}</td>"
            f"<td>{_esc(f.category_label)}</td>"
            f"<td>{_esc(f.scanner)}</td>"
            f"<td><div class=\"title\">{_esc(f.title)}</div>{desc}{rem}</td>"
            f"<td class=\"loc\">{_esc(f.location)}</td>"
            f"<td class=\"id\">{ident}</td>"
            "</tr>"
        )
    return "".join(rows)


_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
       margin: 0; background: #f4f5f7; color: #1f2733; }
header { background: #1f2733; color: #fff; padding: 24px 32px; }
header h1 { margin: 0 0 4px; font-size: 22px; }
header .meta { color: #aeb6c2; font-size: 13px; }
header .meta b { color: #fff; }
main { max-width: 1180px; margin: 0 auto; padding: 24px 32px 60px; }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .04em;
     color: #5b6573; margin: 28px 0 12px; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; }
.card { background: #fff; border-radius: 10px; padding: 16px 22px; min-width: 96px;
        text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.card .num { font-size: 30px; font-weight: 700; line-height: 1; }
.card .lbl { font-size: 11px; color: #7a8694; margin-top: 6px; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
     color: #7a8694; padding: 10px 14px; background: #eef0f3; }
td { padding: 12px 14px; border-top: 1px solid #eef0f3; font-size: 13px; vertical-align: top; }
.scanners td { font-size: 13px; }
.badge { color: #fff; padding: 3px 9px; border-radius: 20px; font-size: 11px;
         font-weight: 700; letter-spacing: .03em; white-space: nowrap; }
.title { font-weight: 600; }
.desc { color: #5b6573; margin-top: 3px; font-size: 12px; }
.rem { color: #2e7d32; margin-top: 4px; font-size: 12px; }
.loc { font-family: Consolas, monospace; color: #34404f; white-space: nowrap; }
.id a { color: #1565c0; text-decoration: none; }
.id { font-family: Consolas, monospace; }
.clean { text-align: center; color: #2e7d32; padding: 32px; font-size: 15px; }
.ok { color: #2e7d32; font-weight: 700; }
.err { color: #c62828; font-weight: 700; }
.muted { color: #7a8694; }
footer { text-align: center; color: #98a2b0; font-size: 12px; padding: 24px; }
"""


def write_html(path, target, target_type, findings, results, summary):
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cat_line = " · ".join(
        f"{CATEGORY_LABELS.get(c, c)}: {n}" for c, n in summary["by_category"].items()
    ) or "—"
    doc = f"""<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecScan hisoboti — {_esc(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>🛡️ SecScan xavfsizlik hisoboti</h1>
  <div class="meta">
    Nishon: <b>{_esc(target)}</b> ({_esc(target_type)}) &nbsp;·&nbsp;
    Sana: <b>{generated}</b> &nbsp;·&nbsp;
    Jami: <b>{summary['total']}</b> ta kamchilik
  </div>
</header>
<main>
  <h2>Daraja bo'yicha</h2>
  <div class="cards">{_summary_cards(summary)}</div>

  <h2>Toifa bo'yicha</h2>
  <p style="color:#5b6573;font-size:13px;margin:0 0 4px">{_esc(cat_line)}</p>

  <h2>Skanerlar</h2>
  <table class="scanners"><tbody>{_scanner_rows(results)}</tbody></table>

  <h2>Topilgan kamchiliklar</h2>
  <table>
    <thead><tr>
      <th>Daraja</th><th>Toifa</th><th>Skaner</th>
      <th>Tavsif</th><th>Joylashuv</th><th>Identifikator</th>
    </tr></thead>
    <tbody>{_finding_rows(findings)}</tbody>
  </table>
</main>
<footer>SecScan · Trivy + Gitleaks + Semgrep · {generated}</footer>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
