"""Skanerlar (toollar) registri.

Har bir tool — alohida `Scanner` klassi. Tool:
  * qaysi nishon turlarini (fs / image / url) qo'llashini bildiradi;
  * Docker buyrug'ini quradi;
  * natijani (fayl yoki stdout) umumiy `Finding` ro'yxatiga aylantiradi.

Yangi tool qo'shish = shu yerga klass + `TOOLS` ro'yxatiga qo'shish.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time

from . import runner
from .model import Finding, ScanResult, Severity


class ScanContext:
    def __init__(self, target, target_type, raw_dir, config,
                 out_mount, out_prefix, src_mount):
        self.target = target            # papka yo'li / image nomi / URL
        self.target_type = target_type  # "fs" | "image" | "url"
        self.raw_dir = raw_dir          # SecScan ko'radigan xom natija papkasi
        self.config = config
        self.out_mount = out_mount      # skaner uchun /out mount satri
        self.out_prefix = out_prefix    # skaner ichida natija yo'li
        self.src_mount = src_mount      # /src mount (image/url uchun None)


# ----------------------------------------------------------------- yordamchilar

def _clean_path(path: str) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/")
    for prefix in ("/src/", "src/"):
        if p.startswith(prefix):
            return p[len(prefix):]
    return p.lstrip("/")


def _trim(text, limit: int = 400) -> str:
    text = str(text or "").strip().replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _write_gitleaks_config(path: str, exclude_dirs) -> None:
    pats = [f"  '''(^|/){re.escape(d)}(/|$)'''," for d in exclude_dirs]
    lines = ["[extend]", "useDefault = true", "", "[allowlist]", "paths = ["]
    lines += pats
    lines.append("]")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _ensure_image_tar(ctx: ScanContext) -> None:
    """Image'ni raw_dir/image.tar ga saqlaydi (bir marta) — Trivy/Grype/Dockle uchun."""
    tar = os.path.join(ctx.raw_dir, "image.tar")
    if os.path.exists(tar):
        return
    proc = runner.docker_save(ctx.target, tar)
    if proc.returncode != 0 or not os.path.exists(tar):
        raise RuntimeError(f"'{ctx.target}' image'ini saqlab bo'lmadi: "
                           + (proc.stderr or "").strip())


def _offline(ctx) -> bool:
    return getattr(ctx.config, "mode", "online") == "offline"


# ----------------------------------------------------------------- asosiy klass

class Scanner:
    key = ""
    title = ""
    category = ""               # sca | secret | sast | misconfig | dast
    target_types = ("fs",)
    default_on = True
    capture_stdout = False      # natija stdout'da bo'lsa True
    entrypoint = None           # docker --entrypoint (kerak bo'lsa)
    user = None                 # docker --user (kerak bo'lsa, masalan ZAP root)
    tolerate_missing = False    # fayl yo'q + xato bo'lsa ham 0 ta deb hisoblash (til-maxsus toollar)
    offline_support = "yes"     # yes = to'liq offline | cache = kesh kerak | no = internet kerak
    out_name = ""               # raw_dir ichidagi natija fayli

    def image(self, ctx):
        raise NotImplementedError

    def command(self, ctx):
        raise NotImplementedError

    def mounts(self, ctx):
        return []

    def env(self, ctx):
        return {}

    def prepare(self, ctx):
        pass

    def parse(self, out_file, ctx):
        raise NotImplementedError

    def run(self, ctx) -> ScanResult:
        start = time.time()
        out_file = os.path.join(ctx.raw_dir, self.out_name)
        try:
            self.prepare(ctx)
            proc = runner.docker_run(self.image(ctx), self.command(ctx),
                                     self.mounts(ctx), timeout=ctx.config.timeout,
                                     entrypoint=self.entrypoint, user=self.user,
                                     env=self.env(ctx))
        except subprocess.TimeoutExpired:
            return ScanResult(self.key, False, f"vaqt tugadi ({ctx.config.timeout}s)",
                              duration=time.time() - start)
        except Exception as exc:  # noqa: BLE001
            return ScanResult(self.key, False, str(exc), duration=time.time() - start)

        dur = time.time() - start

        if self.capture_stdout:
            stdout = proc.stdout or ""
            if not stdout.strip() and proc.returncode != 0:
                tail = (proc.stderr or "").strip().splitlines()
                return ScanResult(self.key, False, " | ".join(tail[-4:]) or "xato",
                                  duration=dur)
            try:
                with open(out_file, "w", encoding="utf-8") as fh:
                    fh.write(stdout)
            except OSError:
                pass

        if not os.path.exists(out_file):
            if proc.returncode == 0 or self.tolerate_missing:
                return ScanResult(self.key, True, findings=[], duration=dur)  # toza
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()
            return ScanResult(self.key, False,
                              " | ".join(tail[-4:]) or "natija fayli yaratilmadi",
                              duration=dur)
        try:
            findings = self.parse(out_file, ctx)
        except Exception as exc:  # noqa: BLE001
            return ScanResult(self.key, False, f"natijani o'qishda xato: {exc}",
                              duration=dur)
        return ScanResult(self.key, True, findings=findings, duration=dur)


# ----------------------------------------------------------------- SCA / image

class TrivyScanner(Scanner):
    key, title, category = "trivy", "Trivy (SCA + IaC)", "sca"
    target_types = ("fs", "image")
    offline_support = "cache"
    out_name = "trivy.json"

    def image(self, ctx):
        return ctx.config.trivy_image

    def prepare(self, ctx):
        if ctx.target_type == "image":
            _ensure_image_tar(ctx)

    def command(self, ctx):
        op = ctx.out_prefix
        common = ["--format", "json", "--output", f"{op}/trivy.json", "--quiet"]
        if _offline(ctx):
            common += ["--skip-db-update", "--skip-java-db-update", "--offline-scan"]
        if ctx.target_type == "image":
            return ["image", "--input", f"{op}/image.tar", "--scanners", "vuln"] + common
        cmd = ["fs", "/src", "--scanners", "vuln,misconfig"] + common
        for d in ctx.config.exclude_dirs:
            cmd += ["--skip-dirs", f"**/{d}"]
        return cmd

    def mounts(self, ctx):
        m = [ctx.out_mount, runner.named_volume("secscan-trivy-cache", "/root/.cache/trivy")]
        if ctx.target_type == "fs" and ctx.src_mount:
            m.insert(0, ctx.src_mount)
        return m

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for result in data.get("Results", []) or []:
            target = _clean_path(result.get("Target", ""))
            for v in result.get("Vulnerabilities", []) or []:
                pkg, fixed = v.get("PkgName", ""), v.get("FixedVersion")
                findings.append(Finding(
                    scanner=self.key, category="sca",
                    severity=Severity.parse(v.get("Severity")),
                    title=f"{pkg}: {v.get('Title') or v.get('VulnerabilityID', '')}",
                    identifier=v.get("VulnerabilityID", ""),
                    description=_trim(v.get("Description", "")), file=target,
                    remediation=(f"{pkg} ni {fixed} versiyaga yangilang" if fixed
                                 else "Tuzatilgan versiya hali yo'q"),
                    reference=v.get("PrimaryURL", "")))
            for m in result.get("Misconfigurations", []) or []:
                cause = m.get("CauseMetadata", {}) or {}
                refs = m.get("References") or []
                findings.append(Finding(
                    scanner=self.key, category="misconfig",
                    severity=Severity.parse(m.get("Severity")),
                    title=f"{m.get('ID', '')}: {m.get('Title', '')}",
                    identifier=m.get("ID", ""), description=_trim(m.get("Description", "")),
                    file=target, start_line=cause.get("StartLine", 0) or 0,
                    remediation=_trim(m.get("Resolution", "")),
                    reference=m.get("PrimaryURL") or (refs[0] if refs else "")))
        return findings


class GrypeScanner(Scanner):
    key, title, category = "grype", "Grype (SCA)", "sca"
    target_types = ("fs", "image")
    capture_stdout = True
    offline_support = "cache"
    out_name = "grype.json"

    def image(self, ctx):
        return ctx.config.grype_image

    def env(self, ctx):
        # Deterministik kesh yo'li (image HOME/user'iga bog'liq bo'lmasin)
        e = {"GRYPE_DB_CACHE_DIR": "/grype-db"}
        if _offline(ctx):
            e["GRYPE_DB_AUTO_UPDATE"] = "false"
        return e

    def prepare(self, ctx):
        if ctx.target_type == "image":
            _ensure_image_tar(ctx)

    def command(self, ctx):
        src = (f"docker-archive:{ctx.out_prefix}/image.tar"
               if ctx.target_type == "image" else "dir:/src")
        return [src, "-o", "json", "-q"]

    def mounts(self, ctx):
        m = [runner.named_volume("secscan-grype-cache", "/grype-db")]
        if ctx.target_type == "image":
            m.append(ctx.out_mount)
        elif ctx.src_mount:
            m.append(ctx.src_mount)
        return m

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for m in data.get("matches", []) or []:
            v = m.get("vulnerability", {}) or {}
            art = m.get("artifact", {}) or {}
            locs = art.get("locations") or []
            fix = (v.get("fix") or {}).get("versions") or []
            findings.append(Finding(
                scanner=self.key, category="sca",
                severity=Severity.parse(v.get("severity")),
                title=f"{art.get('name', '')}: {v.get('id', '')}",
                identifier=v.get("id", ""), description=_trim(v.get("description", "")),
                file=_clean_path(locs[0].get("path", "")) if locs else art.get("name", ""),
                remediation=(f"{art.get('name','')} ni {', '.join(fix)} ga yangilang"
                             if fix else ""),
                reference=v.get("dataSource", "")))
        return findings


class OSVScanner(Scanner):
    key, title, category = "osv", "OSV-Scanner (SCA)", "sca"
    target_types = ("fs",)
    capture_stdout = True
    offline_support = "no"          # OSV.dev API'siga muhtoj
    out_name = "osv.json"

    def image(self, ctx):
        return ctx.config.osv_image

    def command(self, ctx):
        return ["--format", "json", "-r", "/src"]

    def mounts(self, ctx):
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for res in data.get("results", []) or []:
            src = _clean_path((res.get("source", {}) or {}).get("path", ""))
            for pkg in res.get("packages", []) or []:
                p = pkg.get("package", {}) or {}
                for v in pkg.get("vulnerabilities", []) or []:
                    dbs = v.get("database_specific", {}) or {}
                    refs = v.get("references") or []
                    findings.append(Finding(
                        scanner=self.key, category="sca",
                        severity=Severity.parse(dbs.get("severity")),
                        title=f"{p.get('name', '')}: {v.get('id', '')}",
                        identifier=v.get("id", ""),
                        description=_trim(v.get("summary") or v.get("details", "")),
                        file=src,
                        reference=(refs[0].get("url", "") if refs else "")))
        return findings


# ----------------------------------------------------------------- secrets

class GitleaksScanner(Scanner):
    key, title, category = "gitleaks", "Gitleaks (secrets)", "secret"
    target_types = ("fs",)
    out_name = "gitleaks.json"

    def image(self, ctx):
        return ctx.config.gitleaks_image

    def prepare(self, ctx):
        _write_gitleaks_config(os.path.join(ctx.raw_dir, "gitleaks-config.toml"),
                               ctx.config.exclude_dirs)

    def command(self, ctx):
        op = ctx.out_prefix
        return ["dir", "/src", "--config", f"{op}/gitleaks-config.toml",
                "--report-format", "json", "--report-path", f"{op}/gitleaks.json",
                "--redact", "--exit-code", "0"]

    def mounts(self, ctx):
        return [ctx.src_mount, ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for item in data or []:
            rule = item.get("RuleID") or item.get("Rule") or "secret"
            findings.append(Finding(
                scanner=self.key, category="secret", severity=Severity.HIGH,
                title=item.get("Description") or f"Maxfiy kalit: {rule}",
                identifier=rule, description="Topilgan (redacted)",
                file=_clean_path(item.get("File", "")),
                start_line=item.get("StartLine", 0) or 0,
                end_line=item.get("EndLine", 0) or 0,
                remediation="Kalitni koddan olib tashlang, rotate qiling, .env/Vault'da saqlang."))
        return findings


class TruffleHogScanner(Scanner):
    key, title, category = "trufflehog", "TruffleHog (secrets)", "secret"
    target_types = ("fs",)
    capture_stdout = True
    out_name = "trufflehog.json"

    def image(self, ctx):
        return ctx.config.trufflehog_image

    def command(self, ctx):
        cmd = ["filesystem", "/src", "--json", "--no-update"]
        if _offline(ctx):
            cmd.append("--no-verification")   # tirik tekshirish internet talab qiladi
        return cmd

    def mounts(self, ctx):
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        findings = []
        with open(out_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if "DetectorName" not in item:
                    continue
                fs = ((item.get("SourceMetadata", {}) or {}).get("Data", {}) or {}).get("Filesystem", {}) or {}
                verified = item.get("Verified", False)
                det = item.get("DetectorName", "secret")
                findings.append(Finding(
                    scanner=self.key, category="secret",
                    severity=Severity.CRITICAL if verified else Severity.MEDIUM,
                    title=f"{det}" + (" (TASDIQLANGAN — tirik!)" if verified else ""),
                    identifier=det,
                    description="Tasdiqlangan kalit" if verified else "Ehtimoliy kalit",
                    file=_clean_path(fs.get("file", "")),
                    start_line=int(fs.get("line", 0) or 0),
                    remediation="Kalitni rotate qiling va koddan olib tashlang."))
        return findings


# ----------------------------------------------------------------- SAST

class SemgrepScanner(Scanner):
    key, title, category = "semgrep", "Semgrep (SAST)", "sast"
    target_types = ("fs",)
    offline_support = "no"          # `--config auto` qoidalari registry'dan onlayn
    out_name = "semgrep.json"

    def image(self, ctx):
        return ctx.config.semgrep_image

    def command(self, ctx):
        cmd = ["semgrep", "scan", "--config", ctx.config.semgrep_config,
               "--json", "--output", f"{ctx.out_prefix}/semgrep.json",
               "--quiet", "--disable-version-check"]
        for d in ctx.config.exclude_dirs:
            cmd += ["--exclude", d]
        cmd.append("/src")
        return cmd

    def mounts(self, ctx):
        return [ctx.src_mount, ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for r in data.get("results", []) or []:
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            refs = meta.get("references") or []
            cid = r.get("check_id", "")
            findings.append(Finding(
                scanner=self.key, category="sast",
                severity=Severity.parse(extra.get("severity")),
                title=cid.split(".")[-1].replace("-", " ") or "Kod zaifligi",
                identifier=cid, description=_trim(extra.get("message", "")),
                file=_clean_path(r.get("path", "")),
                start_line=(r.get("start", {}) or {}).get("line", 0) or 0,
                end_line=(r.get("end", {}) or {}).get("line", 0) or 0,
                remediation=_trim(meta.get("fix") or extra.get("fix") or ""),
                reference=refs[0] if refs else ""))
        return findings


class BanditScanner(Scanner):
    key, title, category = "bandit", "Bandit (Python SAST)", "sast"
    target_types = ("fs",)
    out_name = "bandit.json"

    def image(self, ctx):
        return ctx.config.bandit_image

    def command(self, ctx):
        return ["-r", "/src", "-f", "json", "-o", f"{ctx.out_prefix}/bandit.json",
                "-q", "--exit-zero"]

    def mounts(self, ctx):
        return [ctx.src_mount, ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for r in data.get("results", []) or []:
            cwe = (r.get("issue_cwe", {}) or {})
            findings.append(Finding(
                scanner=self.key, category="sast",
                severity=Severity.parse(r.get("issue_severity")),
                title=r.get("test_name") or r.get("test_id", "Python zaifligi"),
                identifier=r.get("test_id", ""), description=_trim(r.get("issue_text", "")),
                file=_clean_path(r.get("filename", "")),
                start_line=r.get("line_number", 0) or 0,
                reference=r.get("more_info") or cwe.get("link", "")))
        return findings


# ----------------------------------------------------------------- misconfig / IaC

class HadolintScanner(Scanner):
    key, title, category = "hadolint", "Hadolint (Dockerfile)", "misconfig"
    target_types = ("fs",)
    capture_stdout = True
    entrypoint = "sh"
    out_name = "hadolint.json"

    def image(self, ctx):
        return ctx.config.hadolint_image

    def command(self, ctx):
        script = ("files=$(find /src -iname 'Dockerfile*' "
                  "-not -path '*/node_modules/*' -not -path '*/.venv/*' 2>/dev/null); "
                  "if [ -n \"$files\" ]; then hadolint --format json --no-fail $files; "
                  "else echo '[]'; fi")
        return ["-c", script]

    def mounts(self, ctx):
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for item in data or []:
            code = item.get("code", "")
            findings.append(Finding(
                scanner=self.key, category="misconfig",
                severity=Severity.parse(item.get("level")),
                title=f"{code}: {item.get('message', '')}", identifier=code,
                file=_clean_path(item.get("file", "")),
                start_line=item.get("line", 0) or 0,
                reference=f"https://github.com/hadolint/hadolint/wiki/{code}" if code else ""))
        return findings


class CheckovScanner(Scanner):
    key, title, category = "checkov", "Checkov (IaC)", "misconfig"
    target_types = ("fs",)
    capture_stdout = True
    out_name = "checkov.json"

    def image(self, ctx):
        return ctx.config.checkov_image

    def command(self, ctx):
        return ["-d", "/src", "-o", "json", "--compact", "--soft-fail"]

    def mounts(self, ctx):
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            raw = fh.read()
        # Boshidagi JSON bo'lmagan matnni (banner va h.k.) o'tkazib yuboramiz
        starts = [i for i in (raw.find("["), raw.find("{")) if i != -1]
        if not starts:
            return []
        data = json.loads(raw[min(starts):])
        blocks = data if isinstance(data, list) else [data]
        findings = []
        for block in blocks:
            results = (block.get("results", {}) or {})
            for c in results.get("failed_checks", []) or []:
                lr = c.get("file_line_range") or [0]
                findings.append(Finding(
                    scanner=self.key, category="misconfig",
                    severity=Severity.parse(c.get("severity") or "MEDIUM"),
                    title=f"{c.get('check_id', '')}: {c.get('check_name', '')}",
                    identifier=c.get("check_id", ""),
                    file=_clean_path(c.get("file_path", "")),
                    start_line=lr[0] if lr else 0,
                    reference=c.get("guideline", "") or ""))
        return findings


class DockleScanner(Scanner):
    key, title, category = "dockle", "Dockle (image CIS)", "misconfig"
    target_types = ("image",)
    out_name = "dockle.json"

    def image(self, ctx):
        return ctx.config.dockle_image

    def prepare(self, ctx):
        _ensure_image_tar(ctx)

    def command(self, ctx):
        op = ctx.out_prefix
        return ["--input", f"{op}/image.tar", "--format", "json",
                "--output", f"{op}/dockle.json", "--exit-code", "0"]

    def mounts(self, ctx):
        return [ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for d in data.get("details", []) or []:
            level = (d.get("level") or "").upper()
            if level in ("PASS", "IGNORE", "SKIP", ""):
                continue
            alerts = d.get("alerts") or []
            findings.append(Finding(
                scanner=self.key, category="misconfig",
                severity=Severity.parse(level),
                title=f"{d.get('code', '')}: {d.get('title', '')}",
                identifier=d.get("code", ""), description=_trim("; ".join(alerts)),
                file="(image)",
                reference="https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md"))
        return findings


# ----------------------------------------------------------------- DAST

class NucleiScanner(Scanner):
    key, title, category = "nuclei", "Nuclei (DAST)", "dast"
    target_types = ("url",)
    offline_support = "cache"
    out_name = "nuclei.json"

    def image(self, ctx):
        return ctx.config.nuclei_image

    def command(self, ctx):
        op = ctx.out_prefix
        # -duc YO'Q (onlayn): birinchi marta shablonlarni yuklab olishi uchun (volume'ga keshlanadi)
        cmd = ["-u", ctx.target, "-jsonl", "-o", f"{op}/nuclei.json",
               "-silent", "-no-interactsh"]
        if _offline(ctx):
            cmd.append("-disable-update-check")   # keshlangan shablonlardan
        return cmd

    def mounts(self, ctx):
        return [ctx.out_mount,
                runner.named_volume("secscan-nuclei", "/root/nuclei-templates"),
                runner.named_volume("secscan-nuclei-cfg", "/root/.config/nuclei")]

    def parse(self, out_file, ctx):
        findings = []
        with open(out_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                info = r.get("info", {}) or {}
                ref = info.get("reference") or []
                findings.append(Finding(
                    scanner=self.key, category="dast",
                    severity=Severity.parse(info.get("severity")),
                    title=info.get("name") or r.get("template-id", "Topilma"),
                    identifier=r.get("template-id", ""),
                    description=_trim(f"{r.get('type', '')} @ {r.get('host', '')}"),
                    file=r.get("matched-at") or r.get("host", ""),
                    reference=(ref[0] if isinstance(ref, list) and ref else "")))
        return findings


class TestSSLScanner(Scanner):
    key, title, category = "testssl", "testssl.sh (TLS/SSL)", "dast"
    target_types = ("url",)
    out_name = "testssl.json"

    def image(self, ctx):
        return ctx.config.testssl_image

    def command(self, ctx):
        return ["--jsonfile", f"{ctx.out_prefix}/testssl.json",
                "--quiet", "--color", "0", "--fast", ctx.target]

    def mounts(self, ctx):
        return [ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        rows = data if isinstance(data, list) else data.get("scanResult", [])
        findings = []
        for item in rows or []:
            sev = (item.get("severity") or "").upper()
            if sev in ("OK", "INFO", "DEBUG", ""):
                continue
            findings.append(Finding(
                scanner=self.key, category="dast", severity=Severity.parse(sev),
                title=f"{item.get('id', '')}: {_trim(item.get('finding', ''), 120)}",
                identifier=item.get("cve") or item.get("id", ""),
                description=_trim(item.get("finding", "")), file=ctx.target))
        return findings


class ZapScanner(Scanner):
    key, title, category = "zap", "OWASP ZAP (DAST)", "dast"
    target_types = ("url",)
    default_on = False              # og'ir image + sekin — ixtiyoriy
    user = "root"                   # /zap/wrk (volume) ga yozish uchun
    out_name = "zap.json"

    def image(self, ctx):
        return ctx.config.zap_image

    def _rel(self, ctx):
        return ctx.out_prefix[len("/out"):].lstrip("/")  # "" yoki "scan-x/raw"

    def command(self, ctx):
        rel = self._rel(ctx)
        jf = f"{rel}/zap.json" if rel else "zap.json"
        return ["zap-baseline.py", "-t", ctx.target, "-J", jf, "-I", "-m", "2"]

    def mounts(self, ctx):
        # reports volume'ni /zap/wrk ga ulaymiz (ZAP shu yerga hisobot yozadi)
        return [ctx.out_mount.replace("target=/out", "target=/zap/wrk")]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
        strip = lambda s: _trim(re.sub("<[^>]+>", "", s or ""))
        findings = []
        for site in data.get("site", []) or []:
            for a in site.get("alerts", []) or []:
                insts = a.get("instances") or []
                findings.append(Finding(
                    scanner=self.key, category="dast",
                    severity=Severity.parse(risk.get(str(a.get("riskcode", "0")), "INFO")),
                    title=_trim(a.get("alert", "ZAP topilma"), 140),
                    identifier=a.get("pluginid", ""), description=strip(a.get("desc")),
                    file=(insts[0].get("uri", "") if insts else site.get("@name", "")),
                    remediation=strip(a.get("solution")),
                    reference=strip(a.get("reference"))))
        return findings


# ----------------------------------------------------------------- IaC / SAST (qo'shimcha)

class KicsScanner(Scanner):
    key, title, category = "kics", "KICS (IaC)", "misconfig"
    target_types = ("fs",)
    out_name = "kics.json"

    def image(self, ctx):
        return ctx.config.kics_image

    def command(self, ctx):
        excl = ",".join(f"**/{d}" for d in ctx.config.exclude_dirs)
        return ["scan", "-p", "/src", "--report-formats", "json",
                "-o", ctx.out_prefix, "--output-name", "kics",
                "--no-progress", "--exclude-paths", excl]

    def mounts(self, ctx):
        return [ctx.src_mount, ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for q in data.get("queries", []) or []:
            for f in q.get("files", []) or []:
                findings.append(Finding(
                    scanner=self.key, category="misconfig",
                    severity=Severity.parse(q.get("severity")),
                    title=q.get("query_name", "IaC muammosi"),
                    identifier=q.get("query_id", ""),
                    description=_trim(f.get("issue_type", "")),
                    file=_clean_path(f.get("file_name", "")),
                    start_line=f.get("line", 0) or 0,
                    reference=q.get("query_url", "")))
        return findings


class KubeLinterScanner(Scanner):
    key, title, category = "kubelinter", "kube-linter (K8s)", "misconfig"
    target_types = ("fs",)
    capture_stdout = True
    out_name = "kubelinter.json"

    def image(self, ctx):
        return ctx.config.kubelinter_image

    def command(self, ctx):
        return ["lint", "/src", "--format", "json"]

    def mounts(self, ctx):
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
        if not raw:
            return []
        data = json.loads(raw)
        findings = []
        for r in data.get("Reports", []) or []:
            diag = (r.get("Diagnostic", {}) or {}).get("Message", "")
            meta = (r.get("Object", {}) or {}).get("Metadata", {}) or {}
            findings.append(Finding(
                scanner=self.key, category="misconfig", severity=Severity.MEDIUM,
                title=f"{r.get('Check', '')}", identifier=r.get("Check", ""),
                description=_trim(diag), file=_clean_path(meta.get("FilePath", "")),
                remediation=_trim(r.get("Remediation", ""))))
        return findings


class GosecScanner(Scanner):
    key, title, category = "gosec", "gosec (Go SAST)", "sast"
    target_types = ("fs",)
    tolerate_missing = True     # Go yo'q loyihada xato emas, shunchaki 0 ta
    out_name = "gosec.json"

    def image(self, ctx):
        return ctx.config.gosec_image

    def command(self, ctx):
        return ["-fmt=json", f"-out={ctx.out_prefix}/gosec.json",
                "-no-fail", "-quiet", "/src/..."]

    def mounts(self, ctx):
        return [ctx.src_mount, ctx.out_mount]

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = []
        for r in data.get("Issues", []) or []:
            line = str(r.get("line", "0")).split("-")[0]
            findings.append(Finding(
                scanner=self.key, category="sast",
                severity=Severity.parse(r.get("severity")),
                title=_trim(r.get("details", "Go zaifligi"), 120),
                identifier=r.get("rule_id", ""), description=_trim(r.get("details", "")),
                file=_clean_path(r.get("file", "")),
                start_line=int(line) if line.isdigit() else 0,
                reference=(r.get("cwe", {}) or {}).get("url", "")))
        return findings


class BearerScanner(Scanner):
    key, title, category = "bearer", "Bearer (data/privacy SAST)", "sast"
    target_types = ("fs",)
    capture_stdout = True
    out_name = "bearer.json"

    def image(self, ctx):
        return ctx.config.bearer_image

    def command(self, ctx):
        return ["scan", "/src", "--format", "json", "--exit-code", "0"]

    def mounts(self, ctx):
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            raw = fh.read().strip()
        if not raw:
            return []
        data = json.loads(raw)
        findings = []
        for sev, items in data.items():       # kalit = severity (high/medium/...)
            if not isinstance(items, list):
                continue
            for f in items:
                findings.append(Finding(
                    scanner=self.key, category="sast", severity=Severity.parse(sev),
                    title=f.get("title", "Ma'lumot/xavfsizlik muammosi"),
                    identifier=f.get("id", ""), description=_trim(f.get("description", "")),
                    file=_clean_path(f.get("filename", "")),
                    start_line=f.get("line_number", 0) or 0,
                    reference=f.get("documentation_url", "")))
        return findings


class SyftScanner(Scanner):
    key, title, category = "syft", "Syft (SBOM)", "sbom"
    target_types = ("fs", "image")
    capture_stdout = True
    out_name = "syft.json"

    def image(self, ctx):
        return ctx.config.syft_image

    def prepare(self, ctx):
        if ctx.target_type == "image":
            _ensure_image_tar(ctx)

    def command(self, ctx):
        src = (f"docker-archive:{ctx.out_prefix}/image.tar"
               if ctx.target_type == "image" else "dir:/src")
        return [src, "-o", "json", "-q"]

    def mounts(self, ctx):
        if ctx.target_type == "image":
            return [ctx.out_mount]
        return [ctx.src_mount] if ctx.src_mount else []

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        arts = data.get("artifacts", []) or []
        if not arts:
            return []
        names = ", ".join(f"{a.get('name')}@{a.get('version')}" for a in arts[:6])
        if len(arts) > 6:
            names += f", … (+{len(arts) - 6})"
        # SBOM zaiflik emas — bitta INFO yozuv; to'liq ro'yxat raw/syft.json da
        return [Finding(
            scanner=self.key, category="sbom", severity=Severity.INFO,
            title=f"SBOM: {len(arts)} ta komponent", identifier="syft-sbom",
            description=_trim(f"Komponentlar: {names}. To'liq SBOM: raw/syft.json"),
            file="(SBOM)")]


class KubescapeScanner(Scanner):
    key, title, category = "kubescape", "Kubescape (K8s compliance)", "misconfig"
    target_types = ("fs",)
    offline_support = "cache"           # frameworklar keshlanadi
    tolerate_missing = True
    out_name = "kubescape.json"

    def image(self, ctx):
        return ctx.config.kubescape_image

    def command(self, ctx):
        return ["scan", "/src", "--format", "json",
                "--output", f"{ctx.out_prefix}/kubescape.json"]

    def mounts(self, ctx):
        m = [ctx.out_mount,
             runner.named_volume("secscan-kubescape", "/root/.kubescape")]
        if ctx.src_mount:
            m.insert(0, ctx.src_mount)
        return m

    def parse(self, out_file, ctx):
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
        findings, seen = [], set()
        for res in data.get("results", []) or []:
            for c in res.get("controls", []) or []:
                if (c.get("status") or {}).get("status") != "failed":
                    continue
                cid = c.get("controlID", "")
                if cid in seen:
                    continue
                seen.add(cid)
                findings.append(Finding(
                    scanner=self.key, category="misconfig",
                    severity=Severity.parse(c.get("severity")),
                    title=f"{cid}: {c.get('name', '')}", identifier=cid, file="(k8s)",
                    reference=f"https://hub.armosec.io/docs/{cid.lower()}"))
        return findings


# Tartibli registr (UI shu tartibda ko'rsatadi).
TOOLS = [
    TrivyScanner, GrypeScanner, OSVScanner,                      # sca
    SyftScanner,                                                 # sbom
    GitleaksScanner, TruffleHogScanner,                          # secret
    SemgrepScanner, BanditScanner, GosecScanner, BearerScanner,  # sast
    HadolintScanner, CheckovScanner, KicsScanner,
    KubeLinterScanner, KubescapeScanner, DockleScanner,          # misconfig / IaC
    NucleiScanner, TestSSLScanner, ZapScanner,                   # dast
]
_BY_KEY = {cls.key: cls for cls in TOOLS}


def all_tools_meta():
    """Frontend uchun: barcha toollar ma'lumoti."""
    return [{"key": c.key, "title": c.title, "category": c.category,
             "target_types": list(c.target_types), "default_on": c.default_on,
             "offline_support": c.offline_support}
            for c in TOOLS]


def default_tool_keys():
    return [c.key for c in TOOLS if c.default_on]


def tools_for(selected_keys, target_type):
    """Tanlangan va nishon turini qo'llaydigan tool ob'ektlari."""
    out = []
    for key in selected_keys:
        cls = _BY_KEY.get(key)
        if cls and target_type in cls.target_types:
            out.append(cls())
    return out
