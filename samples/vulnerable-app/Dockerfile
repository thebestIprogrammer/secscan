# DIQQAT: ataylab xato sozlangan Dockerfile — Trivy (misconfig) bularni topadi.
FROM python:3.9

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 5000

# USER ko'rsatilmagan -> konteyner root sifatida ishlaydi (xavfli).
# HEALTHCHECK yo'q. Bularning hammasi Trivy misconfig tekshiruvida chiqadi.
CMD ["python", "app.py"]
