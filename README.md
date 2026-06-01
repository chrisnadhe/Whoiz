# Whoiz - Domain DNS, WHOIS & Network Utility Dashboard

Whoiz adalah aplikasi web dasbor utility modern berbasis Python FastAPI, HTMX, dan Tailwind CSS untuk melakukan pengecekan DNS records secara dinamis, WHOIS lookup, pemantauan propagasi DNS global, pencarian ASN, deteksi IP publik, perhitungan CIDR subnetting, pelacakan vendor MAC Address, pembuatan QR Code secara lokal, serta generator sandi acak yang aman.

---

## 🚀 Fitur Utama

Aplikasi ini dibagi menjadi beberapa modul fungsional:

### 🌐 Network Tools
- **Domain & IP Inspector**: Satu kolom input pintar untuk domain maupun IP Address. Deteksi otomatis berjalan langsung pada backend untuk menampilkan query DNS records secara detail (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV) dan rangkuman informasi WHOIS/RDAP.
- **DNS Propagation**: Pemantauan propagasi DNS global secara asinkron (paralel menggunakan `asyncio.gather`) dari berbagai server DNS publik di berbagai belahan dunia (AS, Eropa, Asia, Australia) dilengkapi data latensi.
- **ASN Lookup**: Melacak nomor ASN langsung, IP, atau domain untuk menampilkan info otorisasi jaringan (registri, nama organisasi, negara, dan tanggal alokasi).
- **What is My IP?**: Deteksi otomatis IP address publik client, tipe protokol (IPv4/IPv6), reverse DNS PTR record, detail User-Agent browser, serta daftar lengkap HTTP Headers request.
- **CIDR Calculator**: Kalkulator subnetting IPv4 terperinci yang menghitung range host, IP pertama & terakhir, alamat broadcast, subnet/wildcard mask, dan jumlah usable host dari input CIDR (e.g. `192.168.1.0/24`).
- **MAC Address Lookup**: Melacak manufaktur/vendor perangkat keras kartu jaringan berdasarkan database OUI (Organizationally Unique Identifier) lokal secara 100% luring (lancar tanpa internet).

### 🛠️ Dev & Security Tools
- **QR Code Generator**: Generator QR Code berkecepatan tinggi yang berjalan 100% di sisi client menggunakan **QRious.js** canvas rendering. Mendukung penyesuaian ukuran piksel, tingkat koreksi error (EC Level), warna foreground & background, pratinjau langsung (*live preview*), dan pengunduhan gambar QR PNG secara instan.
- **Secure Password Generator**: Membuat sandi acak aman kriptografis (modul `secrets` Python) dengan panjang kustom (8-64 karakter), opsi jenis karakter (huruf besar, huruf kecil, angka, simbol), visualisasi tingkat kekuatan keamanan, serta salin satu-klik ke clipboard.

### 🎨 Desain & UI Premium
- **Dark & Light Mode Toggle**: Desain antarmuka modern yang ramah mata. Tema gelap menggunakan Deep Indigo-Gray, sedangkan tema terang beraksen Biru Premium.
- **Responsive Collapsible Sidebar**: Navigasi terstruktur rapi yang ramah perangkat mobile maupun desktop, dapat dikolaps secara dinamis dengan transisi CSS yang halus.
- **HTMX SPA Experience**: Seluruh pergantian halaman menu dan submit form memanfaatkan HTMX untuk pertukaran fragmen HTML secara dinamis tanpa melakukan reload halaman penuh (*Single Page Application*).

---

## 🛠️ Tech Stack

- **Backend**: Python >=3.13, FastAPI, Jinja2, `dnspython`, `python-whois`, `ipwhois`.
- **Testing**: `pytest`, `httpx` (FastAPI TestClient dengan mock network calls).
- **Frontend**: HTMX, Tailwind CSS, QRious.js.
- **Package Manager**: Astral `uv` (cepat, andal, dan modern).
- **Deployment**: Docker (Multi-stage build dengan optimasi Tailwind CSS).

---

## 💻 Cara Menjalankan Lokal

Pastikan Anda sudah menginstal [Astral uv](https://github.com/astral-sh/uv) di mesin Anda.

1. **Clone repository & masuk ke direktori**:
   ```bash
   cd Whoiz
   ```

2. **Sinkronkan dependensi & pasang venv secara otomatis**:
   ```bash
   uv sync
   ```

3. **Jalankan Uvicorn Development Server**:
   ```bash
   uv run uvicorn app.main:app --port 8000 --reload
   ```

4. **Akses aplikasi**:
   Buka browser Anda dan akses [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

## 🧪 Pengujian (Tests Suite)

Aplikasi ini dilengkapi pengujian terstruktur menggunakan `pytest` dan `FastAPI TestClient`. Seluruh pemanggilan jaringan luar (DNS/WHOIS/Socket) telah di-mock agar pengujian dapat dijalankan secara cepat dan 100% offline.

Untuk menjalankan suite pengujian:
```bash
uv run pytest
```

---

## 🐳 Cara Menjalankan dengan Docker (Mode Produksi)

Dalam mode production, Tailwind CSS akan dikompilasi secara otomatis melalui tahap build Node.js di dalam Dockerfile, sehingga container mandiri dan tidak memerlukan koneksi internet untuk memuat Play CDN.

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
```bash
docker compose up -d
```

Aplikasi dapat diakses di [http://localhost:8000](http://localhost:8000).

---

## 📄 Lisensi
[MIT](LICENSE)
