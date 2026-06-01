import os
import asyncio
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.dns_utils import query_dns_records, query_reverse_dns, PROPAGATION_SERVERS, async_query_dns_record, query_asn_details
from app.whois_utils import clean_query, is_ip_address, get_whois_data
import json
import re
import math
import secrets
import string
import ipaddress

# Load MAC Address database lookup on startup
MAC_VENDORS = {}
try:
    with open("app/data/mac_vendors.json", "r", encoding="utf-8") as f:
        mac_data = json.load(f)
        if isinstance(mac_data, list):
            for item in mac_data:
                prefix = item.get("macPrefix", "").upper()
                vendor = item.get("vendorName", "")
                if prefix:
                    MAC_VENDORS[prefix] = vendor
except Exception as e:
    print(f"Error loading mac_vendors.json on startup: {e}")

app = FastAPI(title="Whoiz")

# Pastikan direktori-direktori penting ada sebelum me-mount static files
os.makedirs("app/static", exist_ok=True)
os.makedirs("app/static/css", exist_ok=True)
os.makedirs("app/static/js", exist_ok=True)
os.makedirs("app/templates", exist_ok=True)

# Mount static files directory
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory="app/templates")

RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
    "system": "system"
}

@app.get("/", response_class=HTMLResponse)
async def get_root(request: Request):
    env = os.getenv("APP_ENV", "development")
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "inspector"})

@app.get("/inspector", response_class=HTMLResponse)
async def get_inspector(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "inspector.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "inspector"})

@app.get("/propagation", response_class=HTMLResponse)
async def get_propagation(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "propagation.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "propagation"})

@app.post("/lookup", response_class=HTMLResponse)
async def post_lookup(
    request: Request,
    query: str = Form(""),
    resolver: str = Form("system"),
    custom_resolver_ip: str = Form(""),
    record_types: list[str] = Form(None)
):
    cleaned = clean_query(query)
    if not cleaned:
        error_html = """
        <div class="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-700 dark:text-red-400 rounded-xl flex items-center space-x-2">
            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            <span>Silakan masukkan nama domain atau IP Address yang valid.</span>
        </div>
        """
        return HTMLResponse(content=error_html, status_code=200)
    
    # Tentukan IP resolver yang akan digunakan
    if resolver == "custom":
        resolver_ip = custom_resolver_ip.strip()
        if not resolver_ip:
            resolver_ip = "system"
    else:
        resolver_ip = RESOLVERS.get(resolver, "system")
        
    is_ip = is_ip_address(cleaned)
    
    dns_results = None
    whois_results = None
    reverse_dns = None
    
    if is_ip:
        # Query reverse DNS (PTR) dan IP WHOIS
        reverse_dns = query_reverse_dns(cleaned, None if resolver_ip == "system" else resolver_ip)
        whois_results = get_whois_data(cleaned)
    else:
        # Pengecekan DNS Record & WHOIS Domain
        if not record_types:
            record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        dns_results = query_dns_records(cleaned, None if resolver_ip == "system" else resolver_ip, record_types)
        whois_results = get_whois_data(cleaned)
        
    resolver_display = resolver.upper()
    if resolver == "custom":
        resolver_display = f"CUSTOM ({resolver_ip})"
        
    return templates.TemplateResponse(
        request,
        "results.html",
        {
            "query": cleaned,
            "is_ip": is_ip,
            "dns_results": dns_results,
            "whois_results": whois_results,
            "reverse_dns": reverse_dns,
            "resolver_name": resolver_display
        }
    )

@app.post("/propagation/check", response_class=HTMLResponse)
async def post_propagation_check(
    request: Request,
    domain: str = Form(""),
    record_type: str = Form("A")
):
    cleaned = clean_query(domain)
    if not cleaned:
        error_html = """
        <div class="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-700 dark:text-red-400 rounded-xl flex items-center space-x-2">
            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            <span>Silakan masukkan nama domain yang valid.</span>
        </div>
        """
        return HTMLResponse(content=error_html, status_code=200)

    # Jalankan query secara paralel menggunakan asyncio.gather
    tasks = []
    server_keys = list(PROPAGATION_SERVERS.keys())
    for key in server_keys:
        server_info = PROPAGATION_SERVERS[key]
        tasks.append(async_query_dns_record(cleaned, server_info["ip"], record_type))
        
    results_list = await asyncio.gather(*tasks)
    
    # Susun respon gabungan
    results = {}
    success_count = 0
    total_latency = 0
    resolved_count = 0
    
    for i, key in enumerate(server_keys):
        res = results_list[i]
        server_info = PROPAGATION_SERVERS[key]
        results[key] = {
            "name": server_info["name"],
            "ip": server_info["ip"],
            "location": server_info["location"],
            "flag": server_info["flag"],
            "success": res["success"],
            "values": res["values"],
            "ttl": res["ttl"],
            "latency": res["latency"],
            "error": res["error"]
        }
        # Hitung statistik jika resolusi DNS sukses dan ada nilainya
        if res["success"] and res["error"] != "TIDAK ADA RECORD":
            success_count += 1
            total_latency += res["latency"]
            resolved_count += 1
            
    avg_latency = round(total_latency / resolved_count, 1) if resolved_count > 0 else 0
    
    return templates.TemplateResponse(
        request,
        "propagation_results.html",
        {
            "domain": cleaned,
            "rtype": record_type,
            "results": results,
            "success_count": success_count,
            "total_count": len(server_keys),
            "avg_latency": avg_latency
        }
    )

# ================= 6 NEW FEATURES ROUTE HANDLERS =================

# 1. ASN LOOKUP
@app.get("/asn", response_class=HTMLResponse)
async def get_asn(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "asn_lookup.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "asn"})

@app.post("/asn/lookup", response_class=HTMLResponse)
async def post_asn_lookup(request: Request, query: str = Form("")):
    results = query_asn_details(query)
    return templates.TemplateResponse(request, "asn_lookup.html", {"results": results})

# 2. WHAT IS MY IP
@app.get("/my-ip", response_class=HTMLResponse)
async def get_my_ip(request: Request):
    env = os.getenv("APP_ENV", "development")
    
    # Extract Client IP Address
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.headers.get("x-real-ip", request.client.host)
        
    # Determine protocol version
    ip_version = 6 if ":" in ip else 4
    
    # Get PTR Record (reverse DNS hostname)
    hostname = query_reverse_dns(ip)
    
    user_agent = request.headers.get("user-agent", "Unknown Browser / OS")
    headers_dict = dict(request.headers)
    
    is_htmx = request.headers.get("hx-request") == "true"
    context = {
        "env": env,
        "ip": ip,
        "ip_version": ip_version,
        "hostname": hostname,
        "user_agent": user_agent,
        "headers": headers_dict
    }
    
    if is_htmx:
        return templates.TemplateResponse(request, "my_ip.html", context)
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "my-ip", **context})

# 3. CIDR CALCULATOR
@app.get("/cidr", response_class=HTMLResponse)
async def get_cidr(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "cidr_calc.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "cidr"})

@app.post("/cidr/calculate", response_class=HTMLResponse)
async def post_cidr_calculate(request: Request, query: str = Form("")):
    q = query.strip()
    try:
        if "/" not in q:
            # Assume host route if no mask specified
            q = f"{q}/32"
        network = ipaddress.ip_network(q, strict=False)
        netmask = str(network.netmask)
        wildcard = str(network.hostmask)
        network_address = str(network.network_address)
        broadcast = str(network.broadcast_address)
        
        if network.num_addresses > 2:
            first_usable = str(network[1])
            last_usable = str(network[-2])
            usable_hosts = network.num_addresses - 2
        elif network.num_addresses == 2:
            first_usable = str(network[0])
            last_usable = str(network[1])
            usable_hosts = 2
        else:
            first_usable = str(network[0])
            last_usable = str(network[0])
            usable_hosts = 1
            
        total_hosts = network.num_addresses
        
        results = {
            "success": True,
            "network": str(network),
            "netmask": netmask,
            "wildcard": wildcard,
            "network_address": network_address,
            "broadcast": broadcast,
            "first_usable": first_usable,
            "last_usable": last_usable,
            "usable_hosts": usable_hosts,
            "total_hosts": total_hosts
        }
    except Exception as e:
        results = {
            "success": False,
            "error": f"Format CIDR tidak valid. Pastikan format IP/Prefix benar (misal 192.168.1.0/24). Detail: {str(e)}"
        }
    return templates.TemplateResponse(request, "cidr_calc.html", {"results": results})

# 4. MAC ADDRESS LOOKUP
@app.get("/mac", response_class=HTMLResponse)
async def get_mac(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "mac_lookup.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "mac"})

@app.post("/mac/lookup", response_class=HTMLResponse)
async def post_mac_lookup(request: Request, query: str = Form("")):
    q = query.strip()
    cleaned = re.sub(r'[^0-9A-Fa-f]', '', q).upper()
    
    if len(cleaned) < 6:
        results = {
            "success": False,
            "error": "MAC Address / OUI harus memiliki minimal 6 karakter heksadesimal."
        }
    else:
        prefix_raw = cleaned[:6]
        prefix = f"{prefix_raw[0:2]}:{prefix_raw[2:4]}:{prefix_raw[4:6]}"
        vendor = MAC_VENDORS.get(prefix)
        if vendor:
            results = {
                "success": True,
                "query": q,
                "prefix": prefix,
                "vendor": vendor
            }
        else:
            results = {
                "success": False,
                "error": f"Vendor untuk OUI prefix '{prefix}' tidak ditemukan di database lokal."
            }
    return templates.TemplateResponse(request, "mac_lookup.html", {"results": results})

# 5. QR CODE GENERATOR (Client-side renderer page)
@app.get("/qr", response_class=HTMLResponse)
async def get_qr(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "qr_generator.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "qr"})

# 6. PASSWORD GENERATOR
@app.get("/password", response_class=HTMLResponse)
async def get_password(request: Request):
    env = os.getenv("APP_ENV", "development")
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return templates.TemplateResponse(request, "pass_generator.html", {"env": env})
    return templates.TemplateResponse(request, "index.html", {"env": env, "active_page": "password"})

@app.post("/password/generate", response_class=HTMLResponse)
async def post_password_generate(
    request: Request,
    length: int = Form(16),
    use_upper: str = Form(None),
    use_lower: str = Form(None),
    use_nums: str = Form(None),
    use_syms: str = Form(None)
):
    is_upper = use_upper == "true"
    is_lower = use_lower == "true"
    is_nums = use_nums == "true"
    is_syms = use_syms == "true"
    
    upper_pool = string.ascii_uppercase
    lower_pool = string.ascii_lowercase
    nums_pool = string.digits
    syms_pool = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    pool = ""
    if is_upper: pool += upper_pool
    if is_lower: pool += lower_pool
    if is_nums: pool += nums_pool
    if is_syms: pool += syms_pool
    
    if not pool:
        pool = lower_pool
        is_lower = True
        
    password = "".join(secrets.choice(pool) for _ in range(length))
    
    # Calculate entropy
    pool_size = len(pool)
    entropy = round(length * math.log2(pool_size), 1)
    
    if entropy < 40:
        strength = "Weak"
        strength_id = "Lemah"
    elif entropy < 60:
        strength = "Medium"
        strength_id = "Sedang"
    elif entropy < 80:
        strength = "Strong"
        strength_id = "Kuat"
    else:
        strength = "Very Strong"
        strength_id = "Sangat Kuat"
        
    results = {
        "password": password,
        "entropy": entropy,
        "strength": strength,
        "strength_id": strength_id
    }
    return templates.TemplateResponse(request, "pass_generator.html", {"results": results})
