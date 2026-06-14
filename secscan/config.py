"""Sozlamalar — `.env` faylidan va muhit o'zgaruvchilaridan o'qiladi.

Image versiyalari shu yerda (va `.env` da) markazlashtirilgan, shunda
`docker-compose.yml` bilan bir xil qiymatdan foydalanish mumkin.
"""
from __future__ import annotations

import os

# Standart ravishda skandan chiqarib tashlanadigan papkalar (kutubxonalar,
# build artefaktlari). Bularsiz .venv/node_modules shovqin qo'shadi.
_DEFAULT_EXCLUDES = (
    ".venv,venv,env,.env,node_modules,.git,.hg,.svn,dist,build,out,"
    "__pycache__,.pytest_cache,.mypy_cache,.ruff_cache,.tox,.cache,"
    "site-packages,vendor,.next,.nuxt,.svelte-kit,target,.gradle,"
    ".idea,.vscode,bin,obj,coverage,.terraform"
)


def load_dotenv(path: str) -> None:
    """Oddiy `.env` yuklovchi (tashqi kutubxonasiz).

    Allaqachon o'rnatilgan muhit o'zgaruvchilarini ustiga yozmaydi.
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # inline izohni olib tashlaymiz:  KEY=value   # izoh
            if " #" in value:
                value = value.split(" #", 1)[0].strip()
            os.environ.setdefault(key, value)


class Config:
    """Ishga tushirish sozlamalari."""

    def __init__(self) -> None:
        # Skaner image'lari (versiyani .env orqali pin qilish tavsiya etiladi).
        self.trivy_image = os.getenv("TRIVY_IMAGE", "aquasec/trivy:latest")
        self.gitleaks_image = os.getenv("GITLEAKS_IMAGE", "zricethezav/gitleaks:latest")
        self.semgrep_image = os.getenv("SEMGREP_IMAGE", "semgrep/semgrep:latest")
        self.grype_image = os.getenv("GRYPE_IMAGE", "anchore/grype:latest")
        self.osv_image = os.getenv("OSV_IMAGE", "ghcr.io/google/osv-scanner:latest")
        self.trufflehog_image = os.getenv("TRUFFLEHOG_IMAGE", "trufflesecurity/trufflehog:latest")
        self.bandit_image = os.getenv("BANDIT_IMAGE", "cytopia/bandit:latest")
        self.hadolint_image = os.getenv("HADOLINT_IMAGE", "hadolint/hadolint:latest-alpine")
        self.checkov_image = os.getenv("CHECKOV_IMAGE", "bridgecrew/checkov:latest")
        self.dockle_image = os.getenv("DOCKLE_IMAGE", "goodwithtech/dockle:latest")
        self.nuclei_image = os.getenv("NUCLEI_IMAGE", "projectdiscovery/nuclei:latest")
        self.kics_image = os.getenv("KICS_IMAGE", "checkmarx/kics:latest")
        self.kubelinter_image = os.getenv("KUBELINTER_IMAGE", "stackrox/kube-linter:latest")
        self.gosec_image = os.getenv("GOSEC_IMAGE", "securego/gosec:latest")
        self.testssl_image = os.getenv("TESTSSL_IMAGE", "drwetter/testssl.sh:latest")
        self.zap_image = os.getenv("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
        self.bearer_image = os.getenv("BEARER_IMAGE", "bearer/bearer:latest")
        self.syft_image = os.getenv("SYFT_IMAGE", "anchore/syft:latest")
        self.kubescape_image = os.getenv("KUBESCAPE_IMAGE", "quay.io/kubescape/kubescape-cli:latest")

        # Semgrep ruleset: auto | p/ci | p/owasp-top-ten | p/security-audit ...
        self.semgrep_config = os.getenv("SECSCAN_SEMGREP_CONFIG", "auto")

        # Bitta skanerga ajratilgan maksimal vaqt (sekund).
        self.timeout = int(os.getenv("SECSCAN_TIMEOUT", "900"))

        # CI uchun: shu daraja va undan yuqori topilsa, chiqish kodi != 0.
        self.fail_on = os.getenv("SECSCAN_FAIL_ON", "none").lower()

        # Ishlash rejimi: online (bazalarni yangilaydi) | offline (kesh, internetsiz)
        self.mode = os.getenv("SECSCAN_MODE", "online").lower()

        # Skandan chiqarib tashlanadigan papkalar (vergul bilan).
        self.exclude_dirs = [
            d.strip() for d in
            os.getenv("SECSCAN_EXCLUDE_DIRS", _DEFAULT_EXCLUDES).split(",")
            if d.strip()
        ]

        # Yoqilgan toollar (vergul bilan). Bo'sh bo'lsa, cli standart to'plamni qo'yadi.
        _tools = os.getenv("SECSCAN_TOOLS", "").strip()
        self.tools = {t.strip() for t in _tools.split(",") if t.strip()}
