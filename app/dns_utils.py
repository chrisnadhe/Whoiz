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

