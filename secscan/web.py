"""REST API backend — FastAPI.

Resurs uslubidagi endpointlar (frontend shularni iste'mol qiladi):
  GET  /api/meta          -> versiya + mavjud tekshiruvlar
  POST /api/scans         -> yangi skan boshlaydi (fonda), Scan obyektini qaytaradi
  GET  /api/scans         -> oldingi skanlar (tarix)
  GET  /api/scans/{id}    -> bitta skan holati + jonli log + xulosa
  GET  /reports/...       -> saqlangan HTML/JSON hisobotlar (statik)
  GET  /                  -> build qilingan frontend (frontend/dist), bo'lsa

Skanlar fonda alohida thread'da ishlaydi — API bloklanmaydi.
Avtomatik hujjat: /docs (Swagger), /redoc.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, engine
from .config import Config
from .scanners import TOOLS, all_tools_meta, default_tool_keys

# Loyiha ildizi (web.py -> secscan/secscan/web.py)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRONTEND_DIST = os.path.join(_PROJECT_ROOT, "frontend", "dist")


# ----------------------------------------------------------------- modellar

class ToolInfo(BaseModel):
    key: str
    title: str
    category: str
    target_types: List[str]
    default_on: bool


class Meta(BaseModel):
    version: str
    tools: List[ToolInfo]
    default_target: str
    in_container: bool


class ScanRequest(BaseModel):
    target: str
    type: str = "fs"                       # fs | image | url
    tools: Optional[List[str]] = None      # None -> standart to'plam


class Scan(BaseModel):
    id: str
    status: str                            # running | done | error
    target: str
    type: str
    tools: List[str]
    log: List[str] = []
    summary: Optional[dict] = None
    report_url: Optional[str] = None
    json_url: Optional[str] = None
    error: Optional[str] = None


class HistoryItem(BaseModel):
    name: str
    target: str
    target_type: str
    generated_at: str
    summary: dict
    report_url: str
    json_url: str


def _default_target() -> str:
    """Formada ko'rsatiladigan standart nishon (rejimga qarab)."""
    if os.path.exists("/.dockerenv"):  # konteyner ichida
        for candidate in ("/workspace/samples/vulnerable-app", "/workspace"):
            if os.path.isdir(candidate):
                return candidate
        return "/workspace"
    return "./samples/vulnerable-app"


# Papka "loyiha ildizi" ekanini bildiruvchi marker fayllar.
_PROJECT_MARKERS = {
    "package.json", "pyproject.toml", "requirements.txt", "setup.py",
    "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "composer.json",
    "Gemfile", "Dockerfile", "docker-compose.yml", ".git",
}


def _targets_root() -> str:
    """Loyihalar qidiriladigan ildiz papka (konteynerda /workspace)."""
    if os.path.exists("/.dockerenv"):
        return "/workspace"
    return os.getcwd()


def _list_targets(root: str, exclude, max_depth: int = 4, limit: int = 150):
    """root ichidan loyiha ildizlarini (marker faylga ega papkalar) topadi."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return []
    excl = set(exclude)
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        names = set(filenames) | set(dirnames)        # prune'dan oldin tekshiramiz
        dirnames[:] = sorted(
            d for d in dirnames if d not in excl and not d.startswith(".")
        )
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if names & _PROJECT_MARKERS:
            found.append(dirpath.replace("\\", "/"))
            dirnames[:] = []                            # loyiha ildizi — ichiga kirmaymiz
            if len(found) >= limit:
                break
            continue
        if depth >= max_depth:
            dirnames[:] = []
    return found


def _load_history(reports_dir: str, limit: int = 50) -> List[dict]:
    """reports/ papkasidagi tugagan skanlarni xulosasi bilan o'qiydi."""
    items: List[dict] = []
    if not os.path.isdir(reports_dir):
        return items
    for name in sorted(os.listdir(reports_dir), reverse=True):
        jf = os.path.join(reports_dir, name, "findings.json")
        if not os.path.isfile(jf):
            continue
        try:
            with open(jf, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        items.append({
            "name": name,
            "target": data.get("target", ""),
            "target_type": data.get("target_type", ""),
            "generated_at": data.get("generated_at", ""),
            "summary": data.get("summary", {}),
            "report_url": f"/reports/{name}/report.html",
            "json_url": f"/reports/{name}/findings.json",
        })
        if len(items) >= limit:
            break
    return items


def create_app(reports_dir: str = "reports") -> FastAPI:
    app = FastAPI(
        title="SecScan API",
        version=__version__,
        description="Xavfsizlik skaneri REST API — Trivy + Gitleaks + Semgrep",
    )
    # Frontend dev serveri (Vite) boshqa origin'dan chaqira olishi uchun.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    jobs: Dict[str, dict] = {}
    os.makedirs(reports_dir, exist_ok=True)

    def _run_job(job_id: str, target: str, target_type: str, tools: list):
        job = jobs[job_id]
        job["log"].append(f"Skan boshlandi: {target} ({target_type})")
        try:
            run = engine.run_scan(
                target, target_type, tools,
                output_dir=reports_dir, pull=True,
                progress=lambda m: job["log"].append(m),
            )
            rel_html = os.path.relpath(run.html_path, reports_dir).replace(os.sep, "/")
            rel_json = os.path.relpath(run.json_path, reports_dir).replace(os.sep, "/")
            job["summary"] = run.summary
            job["report_url"] = f"/reports/{rel_html}"
            job["json_url"] = f"/reports/{rel_json}"
            job["status"] = "done"
            job["log"].append(f"Yakunlandi - jami {run.summary['total']} ta kamchilik.")
        except Exception as exc:  # noqa: BLE001
            job["status"] = "error"
            job["error"] = str(exc)
            job["log"].append(f"XATO: {exc}")

    @app.get("/api/meta", response_model=Meta)
    def get_meta():
        return Meta(version=__version__,
                    tools=[ToolInfo(**t) for t in all_tools_meta()],
                    default_target=_default_target(),
                    in_container=os.path.exists("/.dockerenv"))

    @app.post("/api/scans", response_model=Scan, status_code=status.HTTP_201_CREATED)
    def create_scan(req: ScanRequest):
        target = (req.target or "").strip()
        if not target:
            raise HTTPException(400, "Nishon (papka, image yoki URL) ko'rsatilmadi.")
        if req.type not in ("fs", "image", "url"):
            raise HTTPException(400, "type faqat 'fs', 'image' yoki 'url' bo'lishi mumkin.")
        valid = {c.key for c in TOOLS}
        tools = req.tools or default_tool_keys()
        invalid = set(tools) - valid
        if invalid:
            raise HTTPException(400, f"Noma'lum tool: {', '.join(sorted(invalid))}")

        job_id = uuid.uuid4().hex[:12]
        jobs[job_id] = {
            "id": job_id, "status": "running", "target": target,
            "type": req.type, "tools": tools, "log": [],
            "summary": None, "report_url": None, "json_url": None, "error": None,
        }
        threading.Thread(
            target=_run_job, args=(job_id, target, req.type, tools), daemon=True
        ).start()
        return jobs[job_id]

    @app.get("/api/scans", response_model=List[HistoryItem])
    def list_scans():
        return _load_history(reports_dir)

    @app.get("/api/targets")
    def list_targets():
        """/workspace (yoki cwd) ichidagi skanlash mumkin bo'lgan loyihalar."""
        root = _targets_root()
        root_abs = os.path.abspath(root).replace("\\", "/")
        items = []
        for p in _list_targets(root, Config().exclude_dirs):
            rel = os.path.relpath(p, root_abs).replace("\\", "/")
            items.append({"path": p, "label": "(butun papka)" if rel == "." else rel})
        if not any(it["path"] == root_abs for it in items):
            items.insert(0, {"path": root_abs, "label": "(butun papka)"})
        return {"root": root_abs, "targets": items}

    @app.get("/api/scans/{scan_id}", response_model=Scan)
    def get_scan(scan_id: str):
        job = jobs.get(scan_id)
        if not job:
            raise HTTPException(404, "Bunday skan topilmadi.")
        return job

    # Saqlangan hisobotlar (HTML/JSON)
    app.mount("/reports", StaticFiles(directory=reports_dir), name="reports")

    # Build qilingan frontend (eng oxirida — boshqa yo'llarni to'smasligi uchun)
    if os.path.isdir(_FRONTEND_DIST):
        app.mount("/", StaticFiles(directory=_FRONTEND_DIST, html=True), name="frontend")
    else:
        @app.get("/", response_class=HTMLResponse)
        def root_hint():
            return (
                "<h2>SecScan REST API ishlayapti</h2>"
                "<p>Frontend hali build qilinmagan. Variantlar:</p><ul>"
                "<li>Dev rejim: <code>cd frontend &amp;&amp; npm install &amp;&amp; npm run dev</code> "
                "(http://localhost:5173)</li>"
                "<li>Yoki build: <code>cd frontend &amp;&amp; npm run build</code>, "
                "so'ng shu sahifani yangilang.</li></ul>"
                "<p>API hujjati: <a href='/docs'>/docs</a></p>"
            )

    return app
