# Whoiz - Domain DNS & WHOIS Inspector

Whoiz adalah aplikasi web modern berbasis Python FastAPI, HTMX, dan Tailwind CSS untuk melakukan pengecekan DNS records secara dinamis serta WHOIS lookup untuk domain dan alamat IP.

## 🚀 Fitur Utama

- **Unified Dashboard**: Satu kolom input pintar untuk domain maupun IP Address. Deteksi otomatis berjalan langsung pada backend.
- **DNS Resolver Selection**: Pengguna dapat memilih untuk melakukan query DNS via public resolver populer (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`), Default Sistem, atau memasukkan IP DNS kustom sendiri.
- **Dinamis DNS Record Check**: Pengecekan record DNS (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV) secara modular dengan antarmuka checkbox yang bersih.
- **WHOIS Summary & Raw Details**: Hasil WHOIS diparsing menjadi rangkuman kartu informasi penting (Registrar, Created/Expired Date, Nameservers, CIDR, dll.), dilengkapi panel collapsible data teks raw WHOIS.
- **Copy to Clipboard**: Kemudahan menyalin nilai record DNS maupun teks raw WHOIS dengan satu klik.
- **Dark & Light Mode**: Desain responsif bertema modern. Tema terang didominasi warna Putih dan Biru Premium. Tema gelap menggunakan Deep Dark Blue.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.13, FastAPI, Jinja2, `dnspython`, `python-whois`, `ipwhois`.
- **Frontend**: HTMX (untuk pemuatan asinkron SPA tanpa reload halaman), Tailwind CSS (Play CDN untuk local dev, terkompilasi statis untuk docker production).
- **Package Manager**: Astral `uv` (bukan pip biasa).
- **Deployment**: Docker (Multi-stage build).

---

## 💻 Cara Menjalankan Lokal (Windows)

Pastikan Anda sudah memiliki [Astral uv](https://github.com/astral-sh/uv) terinstal di mesin Anda.

1. **Clone repository & masuk ke direktori**:
   ```bash
   cd Whoiz
   ```

2. **Sinkronkan dependensi & jalankan virtual environment**:
   ```bash
   uv sync
   ```

3. **Jalankan Uvicorn Development Server**:
   ```bash
   uv run uvicorn app.main:app --port 8000 --reload
   ```

4. **Akses aplikasi**:
   Buka browser Anda dan buka [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

## 🐳 Cara Menjalankan dengan Docker (Production Mode)

Dalam mode production, Tailwind CSS akan dikompilasi secara otomatis melalui tahap build Node.js di dalam Dockerfile, sehingga container mandiri dan tidak memerlukan koneksi ke Tailwind CDN.

### Menggunakan Docker CLI
1. **Build Docker Image**:
   ```bash
   docker build -t whoiz .
   ```

2. **Jalankan Docker Container**:
   ```bash
   docker run -d --name whoiz_app -p 8000:8000 whoiz
   ```

### Menggunakan Docker Compose
1. **Jalankan Service**:
   ```bash
   docker compose up -d
   ```

Aplikasi dapat diakses di [http://localhost:8000](http://localhost:8000).

---

## 📄 Lisensi
[MIT](LICENSE)
