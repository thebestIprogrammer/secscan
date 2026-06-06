# SecScan — xavfsizlik skaneri va hisobotchi

Loyihani **tayyor ochiq-kodli skanerlar** bilan tekshiradigan va topilgan
kamchiliklarni **bitta umumiy hisobotga** (HTML + JSON) jamlaydigan vosita.

Skanerlar lokalga **o'rnatilmaydi** — har biri o'z rasmiy Docker image'ida
ishlaydi. Orkestratsiya va hisobot — toza Python (tashqi kutubxonasiz).

## Nima tekshiriladi (16 ta tool)

Har bir tool UI/CLI'da **alohida yoqib-o'chiriladi**. Nishon turiga (papka / image /
URL) qarab mos toollar ishlaydi.

| Toifa | Toollar | Nimani topadi |
|-------|---------|---------------|
| **Bog'liqlik / CVE** (SCA) | [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype), [OSV-Scanner](https://github.com/google/osv-scanner) | Kutubxona/paketlardagi ma'lum zaifliklar (uchta turli baza) |
| **Maxfiy kalit** (Secrets) | [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Parol, API token, private key (TruffleHog tirikligini ham tekshiradi) |
| **Kod zaifligi** (SAST) | [Semgrep](https://github.com/semgrep/semgrep), [Bandit](https://github.com/PyCQA/bandit) (Python), [gosec](https://github.com/securego/gosec) (Go) | Koddagi xavfli pattern'lar (SQLi, injection…) |
| **Xato sozlama / IaC** | Trivy, [Hadolint](https://github.com/hadolint/hadolint), [Checkov](https://github.com/bridgecrewio/checkov), [KICS](https://github.com/Checkmarx/kics), [kube-linter](https://github.com/stackrox/kube-linter), [Dockle](https://github.com/goodwithtech/dockle) | Dockerfile, compose, K8s, Terraform, Ansible, Helm; image CIS lint |
| **DAST** (web) | [Nuclei](https://github.com/projectdiscovery/nuclei), [testssl.sh](https://github.com/drwetter/testssl.sh) (TLS), [OWASP ZAP](https://www.zaproxy.org/) | Ishlab turgan web-ilova: shablon skani, TLS/SSL tahlili, baseline DAST |

**Nishon turlari:** `fs` (papka/kod) → SCA, secrets, SAST, IaC toollari · `image`
(Docker image) → Trivy, Grype, Dockle · `url` (DAST) → Nuclei, testssl, ZAP.

> ZAP standart holatda **o'chirilgan** (og'ir image, sekin) — kerak bo'lsa belgilang.

## Talablar

- **Docker Desktop** (ishlab turgan holatda) — skanerlar konteynerda ishlaydi.
  **Docker'da ishga tushirsangiz (pastdagi bo'lim) — boshqa hech narsa kerak emas.**

Lokal (host'da) ishlatish uchun qo'shimcha:
- **Python 3.8+** — CLI uchun tashqi paket **kerak emas**.
  REST API backend uchun: `pip install -r requirements.txt` (FastAPI + uvicorn)
- **Node.js 18+** — faqat React frontendni build/dev qilish uchun

## Docker'da ishga tushirish (eng oson)

Butun ilovani (React frontend + FastAPI backend) bitta konteynerda ishga
tushiradi — host'da Python/Node o'rnatish **shart emas**, faqat Docker kerak:

```powershell
docker compose up -d --build       # http://localhost:8000
docker compose logs -f secscan     # loglar
docker compose down                # to'xtatish
```

Brauzerda **http://localhost:8000** ni oching. Standart holatda shu loyiha
papkasi (`samples/` bilan) `/workspace` ga ulanadi — namuna ilovani darhol
skanlash mumkin.

**O'z kodingizni skanlash — ikki yo'l bor:**

**1) Eng oddiy — hech narsa sozlamasdan.** Formadagi maydonga **istalgan host
papkasi yo'lini tashlang** (masalan `D:\projects\my-app`, yoki Windows "Copy as
path" bilan nusxalangan qo'shtirnoqli yo'l) va **Skanlash** ni bosing. SecScan
o'sha papkani host Docker daemon orqali skanlaydi — `SCAN_DIR` yoki oldindan
ulash **shart emas**.

**2) Loyihalar ro'yxati (ixtiyoriy qulaylik).** `SCAN_DIR` ni loyihalaringiz
turgan papkaga yo'naltirsangiz, forma ulardan **dropdown** yasaydi:

```powershell
# .env faylida:  SCAN_DIR=D:\projects
docker compose up -d
```

SecScan `SCAN_DIR` ichidagi loyihalarni (`package.json`, `pyproject.toml`,
`Dockerfile`, `.git` …) avtomatik topib, ro'yxatga chiqaradi.

> ⚠️ **Xavfsizlik:** veb interfeys host Docker daemon orqali **istalgan host
> papkasini** ulab skanlay oladi. Shuning uchun uni faqat ishonchli, lokal
> muhitda oching (ommaviy tarmoqqa chiqarmang).

**Qanday ishlaydi:** konteyner host Docker soketi (`/var/run/docker.sock`) orqali
skaner konteynerlarini ishga tushiradi (Docker-out-of-Docker). U `docker inspect`
bilan o'z mount'larini aniqlab, `/workspace` ichidagi yo'lni host yo'liga
**avtomatik tarjima** qiladi. Hisobotlar `secscan_reports` named volume'da.

| Buyruq | Vazifa |
|--------|--------|
| `docker compose up -d --build` | qurish va ishga tushirish |
| `docker compose logs -f secscan` | loglar |
| `docker compose down` | to'xtatish (hisobotlar volume'da saqlanadi) |
| `docker compose down -v` | to'xtatish + hisobotlarni ham o'chirish |

> "Tur = Docker image" ham ishlaydi: image host daemon'da mavjud bo'lsa,
> `docker save` orqali skanlanadi (host yo'l tarjimasi kerak emas).

## Lokal (host'da) ishga tushirish — CLI

```powershell
# 1) (ixtiyoriy) sozlamalarni moslash
Copy-Item .env.example .env

# 2) skaner image'larini oldindan yuklab olish (birinchi marta)
python run.py pull

# 3) ataylab zaif namuna loyihani skanlash (demo)
python run.py scan .\samples\vulnerable-app

# 4) hisobotni brauzerda ochish
python run.py scan .\samples\vulnerable-app --open
```

Skan tugagach, natija `reports\scan-<sana>-<vaqt>\` papkasida:

| Fayl | Tarkibi |
|------|---------|
| `report.html` | Odam o'qishi uchun rangli hisobot |
| `findings.json` | Mashina/CI uchun barcha topilmalar |
| `raw\*.json` | Har bir skanerning xom natijasi |

## Veb interfeys (REST API + React)

Arxitektura ikki qismdan iborat:

- **Backend** — FastAPI **REST API** (`secscan/web.py`). Skanlarni boshqaradi,
  JSON qaytaradi. Avtomatik hujjat: `/docs` (Swagger), `/redoc`.
- **Frontend** — alohida **React + Vite** ilovasi (`frontend/`). REST API'ni
  iste'mol qiladi: skan formasi, jonli log, xulosa kartalari, hisobot va tarix.

### Variant A — Dev rejim (ikkita terminal, hot-reload)

```powershell
# 1-terminal: backend (REST API)
pip install -r requirements.txt
python run.py serve                 # http://127.0.0.1:8000  (+ /docs)

# 2-terminal: frontend (Vite dev server)
cd frontend
npm install
npm run dev                         # http://localhost:5173
```

Brauzerda **http://localhost:5173** ni oching. Vite `/api` va `/reports`
so'rovlarini backend (`:8000`) ga **proxy** qiladi — CORS muammosi yo'q.

### Variant B — Yagona server (build + bitta buyruq)

```powershell
cd frontend
npm install
npm run build                       # -> frontend/dist
cd ..
python run.py serve                 # http://127.0.0.1:8000  (frontend + API birga)
```

Build qilingach, FastAPI frontendni `/` da, API'ni `/api` da, hisobotlarni
`/reports` da beradi — hammasi bitta portda.

### REST API endpointlari

| Metod / yo'l | Vazifa |
|--------------|--------|
| `GET /api/meta` | Versiya + mavjud tekshiruvlar (frontend shundan formani quradi) |
| `GET /api/targets` | `/workspace` (yoki cwd) ichidagi skanlash mumkin loyihalar (dropdown uchun) |
| `POST /api/scans` | Yangi skan boshlash (fonda) → `Scan` obyekti |
| `GET /api/scans` | Oldingi skanlar (tarix) |
| `GET /api/scans/{id}` | Bitta skan holati + jonli log + xulosa |
| `GET /reports/...` | Saqlangan HTML/JSON hisobotlar (statik) |

> Skanlar backend'da fonda (thread) ishlaydi — API bloklanmaydi va bir vaqtda
> bir nechta skan bo'lishi mumkin. Server `docker run` ni **host'da** chaqiradi.
> LAN'dan kirish: `python run.py serve --host 0.0.0.0`.

## Buyruqlar

```powershell
python run.py scan <papka|image> [tanlovlar]   # skanlash
python run.py serve [--host H] [--port P]       # veb interfeys
python run.py pull                              # image'larni yuklab olish
python run.py version                           # versiya
```

`python run.py ...` o'rniga `python -m secscan ...` ham ishlaydi.

### `scan` tanlovlari

| Tanlov | Vazifa | Standart |
|--------|--------|----------|
| `--type fs\|image\|url` | `fs` = papka/kod, `image` = Docker image, `url` = DAST | `fs` |
| `--tools` | Vergul bilan tool kalitlari: `trivy,grype,osv,gitleaks,trufflehog,semgrep,bandit,gosec,hadolint,checkov,kics,kubelinter,dockle,nuclei,testssl,zap` | standart (ZAP'siz) |
| `--output <papka>` | Hisobotlar saqlanadigan papka | `reports` |
| `--fail-on <daraja>` | `none\|low\|medium\|high\|critical` — shu daraja+ topilsa chiqish kodi `2` | `none` |
| `--no-pull` | Image'larni avtomatik yuklamaslik (tezroq) | — |
| `--open` | Tugagach HTML hisobotni brauzerda ochish | — |

### Misollar

```powershell
# Faqat ayrim toollar bilan
python run.py scan .\my-project --tools semgrep,bandit,gitleaks

# Boshqa papkadagi haqiqiy loyihani skanlash
python run.py scan C:\code\my-app --open

# Docker image'ni skanlash (Trivy + Grype + Dockle)
python run.py scan nginx:1.21 --type image

# Ishlab turgan web-ilovani tekshirish (DAST — Nuclei)
python run.py scan https://example.com --type url
```

## CI/CD ga ulash

Standalone CLI bo'lsa-da, `--fail-on` chiqish kodi tufayli uni pipeline'ga
qo'yish oson. Masalan, **GitLab CI** (`.gitlab-ci.yml`):

```yaml
security_scan:
  stage: test
  script:
    - python run.py scan . --fail-on high --no-pull
  # chiqish kodi 2 bo'lsa, bosqich "failed" bo'ladi va merge to'xtaydi
```

**Jenkins** (`Jenkinsfile`):

```groovy
stage('Security Scan') {
  steps { sh 'python run.py scan . --fail-on high' }
}
```

## Sozlamalar (`.env`)

Image versiyalari va standart sozlamalar `.env` orqali boshqariladi
(`.env.example` dan nusxa oling). Bir xil image versiyalari `docker-compose.yml`
da ham ishlatiladi — barchasini oldindan yuklash uchun:

```powershell
docker compose --profile tools pull
```

| O'zgaruvchi | Vazifa |
|-------------|--------|
| `SCAN_DIR` | Docker rejimida `/workspace` ga ulanadigan host papkasi |
| `TRIVY_IMAGE` / `GITLEAKS_IMAGE` / `SEMGREP_IMAGE` | Skaner image versiyalari |
| `SECSCAN_SEMGREP_CONFIG` | Semgrep ruleset (`auto`, `p/owasp-top-ten`, …) |
| `SECSCAN_EXCLUDE_DIRS` | Skandan chiqariladigan papkalar (standart: `.venv`, `node_modules`, …) |
| `SECSCAN_TIMEOUT` | Bitta skanerga ajratilgan maksimal vaqt (s) |
| `SECSCAN_FAIL_ON` | CI gate darajasi (CLI `--fail-on` ustun keladi) |

> Standart ravishda `.venv`, `node_modules`, `.git`, `dist`, `build`,
> `site-packages` va shunga o'xshash kutubxona/artefakt papkalari skandan
> **chiqarib tashlanadi** (shovqinning oldini oladi). To'liq ro'yxatni
> `SECSCAN_EXCLUDE_DIRS` orqali o'zgartirish mumkin.

## Loyiha tuzilmasi

```
secscan/
├── run.py                     # qulay ishga tushiruvchi
├── Dockerfile                 # frontend build + backend + docker CLI (bitta image)
├── docker-compose.yml         # secscan xizmati (DooD) + skaner prefetch
├── requirements.txt           # backend uchun (FastAPI + uvicorn)
├── .env.example               # sozlamalar namunasi
├── secscan/                   # Python paketi (backend + CLI)
│   ├── cli.py                 # CLI (scan / serve / pull / version)
│   ├── engine.py              # skan dvigateli (CLI + REST API birga ishlatadi)
│   ├── web.py                 # FastAPI REST API backend
│   ├── scanners.py            # Trivy / Gitleaks / Semgrep
│   ├── model.py               # umumiy Finding modeli
│   ├── runner.py              # Docker yordamchilari
│   ├── report.py              # konsol + HTML + JSON hisobot
│   └── config.py              # .env sozlamalari
├── frontend/                  # React + Vite (TypeScript) frontend
│   ├── src/
│   │   ├── App.tsx            # asosiy komponent (holat, polling)
│   │   ├── api.ts             # REST API mijozi + tiplar
│   │   └── components/        # ScanForm, StatusPanel, ResultPanel, HistoryTable
│   ├── vite.config.ts         # dev proxy -> backend :8000
│   └── package.json
├── samples/vulnerable-app/    # ATAYLAB zaif namuna (sinash uchun)
└── reports/                   # skan natijalari (git'ga tushmaydi)
```

## Eslatmalar

- `samples/vulnerable-app/` **ataylab zaif** yozilgan — faqat SecScan'ni sinash
  uchun. Undagi "kalitlar" soxta. Hech qachon production'da ishlatmang.
- Yangi skaner qo'shish = `secscan/scanners.py` ga yana bitta klass yozib,
  `SCANNERS` ro'yxatiga qo'shish.
- `--type image` lokal image'ni `docker save` orqali `.tar` ga saqlab skanlaydi,
  shuning uchun Docker soketini ulash shart emas (Windows'da ishonchli).
- Gitleaks topgan kalitlar hisobotga **REDACTED** ko'rinishida yoziladi —
  haqiqiy qiymat oshkor bo'lmaydi.
