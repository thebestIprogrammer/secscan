"""DIQQAT: bu ATAYLAB zaif yozilgan namuna ilova.

Faqat SecScan'ni sinash uchun. Hech qachon production'da ishlatmang!
Bu yerda Semgrep/Bandit (SAST) topadigan kod zaifliklari bor; bog'liqliklar
(requirements.txt) va Dockerfile esa SCA/misconfig'ni sinaydi.
"""
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# Eslatma: maxfiy kalit (secrets) demosi shu yerda EDI, lekin ochiq repoda GitHub
# "push protection" bloklamasligi uchun olib tashlandi. Gitleaks/TruffleHog ni
# sinash uchun o'zingizning (soxta) kalitingizni shu yerga qo'shib ko'ring.


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL injection — foydalanuvchi kiritmasi to'g'ridan-to'g'ri so'rovga qo'shilmoqda
    cur = conn.execute("SELECT * FROM users WHERE id = '%s'" % uid)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection — shell=True bilan foydalanuvchi kiritmasi
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load")
def load_config():
    raw = request.args.get("data")
    # Xavfli deserializatsiya — yaml.load(Loader'siz) ixtiyoriy obyekt yaratadi
    return str(yaml.load(raw))


if __name__ == "__main__":
    # debug=True production'da xavfli (kod ijro etish mumkin)
    app.run(host="0.0.0.0", debug=True)
