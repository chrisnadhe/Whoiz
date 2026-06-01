import re
import ipaddress
import json
import whois
from ipwhois import IPWhois

def clean_query(query: str) -> str:
    """
    Membersihkan query input dari protokol (http/https), port, path, dan spasi.
    """
    q = query.strip()
    # Hapus skema/protokol
    q = re.sub(r'^https?://', '', q, flags=re.IGNORECASE)
    # Hapus path (apapun setelah /)
    q = q.split('/')[0]
    # Hapus port (apapun setelah :)
    q = q.split(':')[0]
    return q

def is_ip_address(query: str) -> bool:
    """
    Memeriksa apakah string query adalah IP Address (IPv4 / IPv6) yang valid.
    """
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False

def format_string_or_list(val) -> str:
    """
    Helper untuk memformat string atau list menjadi representasi teks comma-separated.
    """
    if not val:
        return "N/A"
    if isinstance(val, list):
        filtered = []
        for item in val:
            if item:
                # Konversi datetime atau objek lain ke string
                item_str = str(item).strip()
                if item_str and item_str not in filtered:
                    filtered.append(item_str)
        return ", ".join(filtered) if filtered else "N/A"
    return str(val).strip()

def format_date(val) -> str:
    """
    Helper untuk memformat object tanggal/datetime menjadi format string yang rapi.
    """
    if not val:
        return "N/A"
    if isinstance(val, list):
        # Ambil tanggal pertama jika berupa list
        val = val[0]
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S")
    except AttributeError:
        return str(val)

def lookup_domain_whois(domain: str) -> dict:
    """
    Melakukan query WHOIS untuk nama domain.
    """
    try:
        # Panggil library python-whois
        w = whois.whois(domain)
        
        # Ekstrak data terformat
        registrar = format_string_or_list(w.get("registrar"))
        creation_date = format_date(w.get("creation_date"))
        expiration_date = format_date(w.get("expiration_date"))
        updated_date = format_date(w.get("updated_date"))
        nameservers = format_string_or_list(w.get("name_servers"))
        status = format_string_or_list(w.get("status"))
        raw_text = w.text or "Tidak ada data teks WHOIS mentah."
        
        # Deteksi apakah domain terdaftar (python-whois terkadang return objek kosong tanpa melempar error)
        is_registered = True
        if registrar == "N/A" and creation_date == "N/A" and expiration_date == "N/A":
            is_registered = False
            
        if not is_registered:
            return {
                "type": "domain",
                "success": False,
                "error": "Domain tampaknya belum terdaftar atau tidak ditemukan di server WHOIS.",
                "raw": raw_text
            }

        return {
            "type": "domain",
            "success": True,
            "summary": {
                "domain": domain,
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "updated_date": updated_date,
                "nameservers": nameservers,
                "status": status
            },
            "raw": raw_text
        }
    except whois.parser.PywhoisError as e:
        return {
            "type": "domain",
            "success": False,
            "error": f"Domain tidak ditemukan atau tidak terdaftar. Detail: {str(e)}",
            "raw": str(e)
        }
    except Exception as e:
        return {
            "type": "domain",
            "success": False,
            "error": f"Error WHOIS Domain: {str(e)}",
            "raw": f"Error: {str(e)}"
        }

def lookup_ip_whois(ip_addr: str) -> dict:
    """
    Melakukan query WHOIS/RDAP untuk IP Address.
    """
    try:
        obj = IPWhois(ip_addr)
        # Query menggunakan RDAP (Registration Data Access Protocol)
        rdap_res = obj.lookup_rdap(depth=1)
        
        network = rdap_res.get("network", {})
        cidr = network.get("cidr")
        net_name = network.get("name")
        
        descr_val = network.get("description")
        if isinstance(descr_val, list):
            descr = "\n".join([str(d) for d in descr_val])
        else:
            descr = str(descr_val) if descr_val else "N/A"
            
        country = network.get("country")
        asn = rdap_res.get("asn")
        asn_desc = rdap_res.get("asn_description")
        
        # Format raw JSON data
        raw_data = json.dumps(rdap_res, indent=2, default=str)
        
        return {
            "type": "ip",
            "success": True,
            "summary": {
                "ip": ip_addr,
                "cidr": cidr or "N/A",
                "net_name": net_name or "N/A",
                "asn": f"AS{asn}" if asn else "N/A",
                "asn_desc": asn_desc or "N/A",
                "country": country or "N/A",
                "description": descr
            },
            "raw": raw_data
        }
    except Exception as e:
        return {
            "type": "ip",
            "success": False,
            "error": f"Gagal mengambil WHOIS IP: {str(e)}",
            "raw": f"Error: {str(e)}"
        }

def get_whois_data(query: str) -> dict:
    """
    Fungsi entri utama untuk mendapatkan data WHOIS.
    Mendeteksi secara otomatis apakah input berupa IP atau Domain.
    """
    clean_q = clean_query(query)
    if not clean_q:
        return {
            "type": "unknown",
            "success": False,
            "error": "Query kosong atau tidak valid.",
            "raw": ""
        }
        
    if is_ip_address(clean_q):
        return lookup_ip_whois(clean_q)
    else:
        return lookup_domain_whois(clean_q)
