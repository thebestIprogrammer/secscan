"""Docker bilan ishlash — skanerlarni konteynerda ishga tushirish yordamchilari.

Skanerlar lokalga o'rnatilmaydi; har biri o'z rasmiy Docker image'ida ishlaydi.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess


class DockerError(RuntimeError):
    pass


def ensure_docker() -> None:
    """Docker mavjud va ishlab turganini tekshiradi."""
    if shutil.which("docker") is None:
        raise DockerError(
            "Docker topilmadi. Docker Desktop o'rnatilgan va PATH'da ekanini tekshiring."
        )
    proc = subprocess.run(
        ["docker", "info"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise DockerError(
            "Docker daemon javob bermayapti. Docker Desktop ishga tushganini tekshiring.\n"
            + (proc.stderr or "").strip()
        )


def host_path(path: str) -> str:
    """Windows yo'lini Docker mount uchun normallashtiradi (\\ -> /)."""
    return os.path.abspath(path).replace("\\", "/")


def bind(src: str, target: str, read_only: bool = False) -> str:
    """`--mount` uchun bind-mount satri (drive harfidagi `:` muammosini chetlab o'tadi)."""
    spec = f"type=bind,source={host_path(src)},target={target}"
    if read_only:
        spec += ",readonly"
    return spec


def named_volume(name: str, target: str) -> str:
    """`--mount` uchun named volume satri (masalan, Trivy bazasini keshlash)."""
    return f"type=volume,source={name},target={target}"


def docker_run(image: str, command, mounts=None, timeout: int = 900,
               entrypoint=None, user=None):
    """`docker run --rm` ni mount'lar bilan ishga tushiradi va natijani qaytaradi."""
    cmd = ["docker", "run", "--rm"]
    for mount in mounts or []:
        cmd += ["--mount", mount]
    if entrypoint is not None:
        cmd += ["--entrypoint", entrypoint]
    if user is not None:
        cmd += ["--user", user]
    cmd += [image] + list(command)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_pull(image: str):
    """Image'ni oldindan yuklab oladi (birinchi skan tezroq bo'lishi uchun)."""
    return subprocess.run(["docker", "pull", image], capture_output=True, text=True)


def docker_save(image_ref: str, out_tar: str):
    """Lokal image'ni .tar ga saqlaydi — Trivy uni `--input` orqali skanlaydi.

    Bu Docker soketini konteynerga ulashdan ko'ra Windows'da ishonchliroq.
    """
    return subprocess.run(
        ["docker", "save", image_ref, "-o", out_tar],
        capture_output=True,
        text=True,
    )


# ----------------------------------------------------------------------------
# Konteyner rejimi (Docker-out-of-Docker)
#
# SecScan konteyner ICHIDA ishlaganda, u ishga tushiradigan skaner konteynerlari
# uchun bind-mount manbalari HOST daemon tomonidan talqin qilinadi — ya'ni
# SecScan konteynerining ichki yo'llari emas, host yo'llari kerak.
# Buni hal qilish uchun konteyner o'zini `docker inspect` qilib, o'z mount'larini
# (qaysi host yo'li/volume qayerga ulangani) bilib oladi va shu xaritaga ko'ra
# skaner mount'larini quradi. Host rejimida bu hammasi o'tkazib yuboriladi.
# ----------------------------------------------------------------------------

_mount_map = None  # keshlangan: [{type, name, source, dest}, ...]


def in_container() -> bool:
    """SecScan konteyner ichida ishlayaptimi?"""
    return os.path.exists("/.dockerenv")


def _self_id():
    cid = os.environ.get("HOSTNAME")
    if cid:
        return cid
    try:
        with open("/etc/hostname", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _discover_mounts():
    """O'z konteynerining mount'larini `docker inspect` orqali aniqlaydi."""
    global _mount_map
    if _mount_map is not None:
        return _mount_map
    _mount_map = []
    cid = _self_id()
    if not cid:
        return _mount_map
    proc = subprocess.run(
        ["docker", "inspect", cid, "--format", "{{json .Mounts}}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return _mount_map
    try:
        for m in json.loads(proc.stdout or "[]"):
            _mount_map.append({
                "type": m.get("Type"), "name": m.get("Name"),
                "source": m.get("Source"), "dest": m.get("Destination"),
            })
    except ValueError:
        pass
    return _mount_map


def _covering_mount(path: str):
    """`path` (konteyner ichidagi yo'l) qaysi mount ichida ekanini topadi."""
    best = None
    for m in _discover_mounts():
        dest = m.get("dest")
        if not dest:
            continue
        if path == dest or path.startswith(dest.rstrip("/") + "/"):
            if best is None or len(dest) > len(best["dest"]):
                best = m
    return best


def plan_out_mount(raw_dir: str):
    """Skaner uchun /out mount'ini va natija fayllari prefiksini qaytaradi.

    -> (mount_satri, prefiks)   masalan: ("type=volume,...", "/out/scan-x/raw")
    """
    raw_abs = os.path.abspath(raw_dir)
    if in_container():
        m = _covering_mount(raw_abs)
        if m:
            rel = os.path.relpath(raw_abs, m["dest"]).replace(os.sep, "/")
            if m["type"] == "volume" and m.get("name"):
                mount = f"type=volume,source={m['name']},target=/out"
            else:
                src = (m["source"] or "").replace("\\", "/")
                mount = f"type=bind,source={src},target=/out"
            prefix = "/out" if rel in (".", "") else f"/out/{rel}"
            return mount, prefix
    return bind(raw_dir, "/out"), "/out"


def plan_src_mount(target: str, read_only: bool = True):
    """Skaner uchun /src (skanlanadigan papka) mount satrini qaytaradi.

    Konteyner rejimida:
      * agar yo'l ulangan papka ichida bo'lsa (masalan /workspace/...) -> uni
        host manbasiga tarjima qilamiz;
      * aks holda yo'lni XOM host yo'li deb hisoblaymiz va to'g'ridan-to'g'ri
        beramiz — skaner konteynerini host daemon ishga tushirgani uchun u
        istalgan host papkasini ulay oladi (SCAN_DIR/mount shart emas).
    """
    if in_container():
        m = _covering_mount(target) if target.startswith("/") else None
        if m:
            rel = os.path.relpath(target, m["dest"]).replace(os.sep, "/")
            base = (m["source"] or "").rstrip("/\\")
            src = base if rel in (".", "") else f"{base}/{rel}"
        else:
            src = target  # xom host yo'li
        src = src.replace("\\", "/")
        spec = f"type=bind,source={src},target=/src"
        if read_only:
            spec += ",readonly"
        return spec
    return bind(target, "/src", read_only=read_only)
