import dns.resolver
import dns.exception

def query_dns_records(domain: str, resolver_ip: str | None = None, record_types: list[str] | None = None) -> dict:
    """
    Melakukan query DNS records menggunakan dnspython.
    
    Args:
        domain (str): Nama domain yang akan di-query.
        resolver_ip (str | None): IP Public DNS Resolver. Jika None atau "system", menggunakan default system.
        record_types (list[str] | None): Daftar record types yang akan dicek.
        
    Returns:
        dict: Hasil query terkelompok berdasarkan tipe record.
    """
    if not record_types:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        
    resolver = dns.resolver.Resolver()
    
    # Konfigurasi custom resolver jika disediakan
    if resolver_ip and resolver_ip.strip() != "" and resolver_ip.lower() != "system":
        resolver.nameservers = [resolver_ip.strip()]
        
    # Timeout settings
    resolver.timeout = 2.5
    resolver.lifetime = 2.5
    
    results = {}
    
    for rtype in record_types:
        results[rtype] = {
            "records": [],
            "error": None
        }
        
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                record_info = {}
                
                # Parsing detail berdasarkan jenis record
                if rtype == "A":
                    record_info["value"] = rdata.address
                elif rtype == "AAAA":
                    record_info["value"] = rdata.address
                elif rtype == "MX":
                    # Menghilangkan titik di akhir hostname
                    exchange_str = rdata.exchange.to_text().rstrip(".")
                    record_info["value"] = f"{rdata.preference} {exchange_str}"
                    record_info["preference"] = rdata.preference
                    record_info["exchange"] = exchange_str
                elif rtype == "TXT":
                    # Gabungkan byte strings jika ada banyak string dalam satu record TXT
                    txt_parts = []
                    for string in rdata.strings:
                        try:
                            txt_parts.append(string.decode("utf-8", errors="replace"))
                        except Exception:
                            txt_parts.append(str(string))
                    record_info["value"] = "".join(txt_parts)
                elif rtype == "NS":
                    record_info["value"] = rdata.target.to_text().rstrip(".")
                elif rtype == "CNAME":
                    record_info["value"] = rdata.target.to_text().rstrip(".")
                elif rtype == "SOA":
                    mname = rdata.mname.to_text().rstrip(".")
                    rname = rdata.rname.to_text().rstrip(".")
                    record_info["value"] = (
                        f"Primary NS: {mname}, Admin Email: {rname}, Serial: {rdata.serial}"
                    )
                    record_info["mname"] = mname
                    record_info["rname"] = rname
                    record_info["serial"] = rdata.serial
                    record_info["refresh"] = rdata.refresh
                    record_info["retry"] = rdata.retry
                    record_info["expire"] = rdata.expire
                    record_info["minimum"] = rdata.minimum
                elif rtype == "CAA":
                    try:
                        tag = rdata.tag.decode("utf-8", errors="replace")
                    except Exception:
                        tag = str(rdata.tag)
                    try:
                        val = rdata.value.decode("utf-8", errors="replace")
                    except Exception:
                        val = str(rdata.value)
                    record_info["value"] = f"{rdata.flags} {tag} {val}"
                elif rtype == "SRV":
                    target_str = rdata.target.to_text().rstrip(".")
                    record_info["value"] = f"{rdata.priority} {rdata.weight} {rdata.port} {target_str}"
                else:
                    record_info["value"] = rdata.to_text()
                
                record_info["ttl"] = answers.ttl
                results[rtype]["records"].append(record_info)
                
        except dns.resolver.NoAnswer:
            # Tidak ada record tipe ini pada domain tersebut (bukan error fatal)
            continue
        except dns.resolver.NXDOMAIN:
            # Domain tidak terdaftar
            for r in record_types:
                results[r]["error"] = "Domain tidak ditemukan (NXDOMAIN)"
            break
        except dns.resolver.NoNameservers:
            results[rtype]["error"] = "Nameserver DNS tidak merespon atau menolak query"
        except dns.exception.Timeout:
            results[rtype]["error"] = "Query timeout (DNS resolver tidak merespon)"
        except Exception as e:
            results[rtype]["error"] = f"Error: {str(e)}"
            
    return results

def query_reverse_dns(ip_addr: str, resolver_ip: str | None = None) -> str:
    """
    Melakukan reverse DNS lookup (PTR record) untuk IP address.
    """
    import dns.reversename
    try:
        resolver = dns.resolver.Resolver()
        if resolver_ip and resolver_ip.strip() != "" and resolver_ip.lower() != "system":
            resolver.nameservers = [resolver_ip.strip()]
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        rev_name = dns.reversename.from_address(ip_addr)
        answers = resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            return rdata.target.to_text().rstrip(".")
    except Exception:
        pass
    return "Tidak ditemukan (No PTR Record)"

# Daftar public DNS server global untuk pengecekan propagasi
PROPAGATION_SERVERS = {
    "us-cloudflare": {"name": "Cloudflare DNS", "ip": "1.1.1.1", "location": "North America", "flag": "🇺🇸"},
    "us-google": {"name": "Google Public DNS", "ip": "8.8.8.8", "location": "North America", "flag": "🇺🇸"},
    "us-opendns": {"name": "OpenDNS", "ip": "208.67.222.222", "location": "North America", "flag": "🇺🇸"},
    "ch-quad9": {"name": "Quad9", "ip": "9.9.9.9", "location": "Europe", "flag": "🇨🇭"},
    "ru-yandex": {"name": "Yandex DNS", "ip": "77.88.8.8", "location": "Europe", "flag": "🇷🇺"},
    "at-cleanbrowsing": {"name": "CleanBrowsing", "ip": "185.228.168.9", "location": "Europe", "flag": "🇦🇹"},
    "cn-alibaba": {"name": "Alibaba DNS", "ip": "223.5.5.5", "location": "Asia", "flag": "🇨🇳"},
    "sg-adguard": {"name": "AdGuard DNS", "ip": "94.140.14.14", "location": "Asia", "flag": "🇸🇬"},
    "hk-dnssb": {"name": "DNS.SB", "ip": "185.222.222.222", "location": "Asia", "flag": "🇭🇰"},
    "au-telstra": {"name": "Telstra DNS", "ip": "139.130.4.4", "location": "Oceania", "flag": "🇦🇺"},
    "br-level3": {"name": "Level3 DNS", "ip": "209.244.0.3", "location": "South America", "flag": "🇧🇷"},
}

async def async_query_dns_record(domain: str, resolver_ip: str, rtype: str) -> dict:
    """
    Melakukan query DNS secara asinkron untuk resolver tertentu.
    Mengukur waktu respon (latency).
    """
    import time
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
    
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    start_time = time.perf_counter()
    try:
        answers = await resolver.resolve(domain, rtype)
        latency = (time.perf_counter() - start_time) * 1000  # ms
        
        values = []
        for rdata in answers:
            if rtype == "A" or rtype == "AAAA":
                values.append(rdata.address)
            elif rtype == "MX":
                values.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
            elif rtype == "TXT":
                parts = []
                for string in rdata.strings:
                    try:
                        parts.append(string.decode("utf-8", errors="replace"))
                    except Exception:
                        parts.append(str(string))
                values.append("".join(parts))
            elif rtype in ["NS", "CNAME"]:
                values.append(rdata.target.to_text().rstrip("."))
            elif rtype == "SOA":
                values.append(f"Primary NS: {rdata.mname.to_text().rstrip('.')}, Admin: {rdata.rname.to_text().rstrip('.')}, Serial: {rdata.serial}")
            elif rtype == "CAA":
                try:
                    tag = rdata.tag.decode("utf-8", errors="replace")
                except Exception:
                    tag = str(rdata.tag)
                try:
                    val = rdata.value.decode("utf-8", errors="replace")
                except Exception:
                    val = str(rdata.value)
                values.append(f"{rdata.flags} {tag} {val}")
            elif rtype == "SRV":
                values.append(f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target.to_text().rstrip('.')}")
            else:
                values.append(rdata.to_text())
                
        return {
            "success": True,
            "values": values,
            "ttl": answers.ttl,
            "latency": round(latency, 1),
            "error": None
        }
    except dns.resolver.NoAnswer:
        latency = (time.perf_counter() - start_time) * 1000
        return {
            "success": True,
            "values": [],
            "ttl": 0,
            "latency": round(latency, 1),
            "error": "TIDAK ADA RECORD"
        }
    except dns.resolver.NXDOMAIN:
        return {
            "success": False,
            "values": [],
            "ttl": 0,
            "latency": 0,
            "error": "NXDOMAIN (Domain tidak ditemukan)"
        }
    except dns.exception.Timeout:
        return {
            "success": False,
            "values": [],
            "ttl": 0,
            "latency": 0,
            "error": "Timeout (Resolver tidak merespon)"
        }
    except Exception as e:
        return {
            "success": False,
            "values": [],
            "ttl": 0,
            "latency": 0,
            "error": str(e)
        }


