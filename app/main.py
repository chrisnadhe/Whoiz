import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.dns_utils import query_dns_records, query_reverse_dns
from app.whois_utils import clean_query, is_ip_address, get_whois_data

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
async def get_index(request: Request):
    env = os.getenv("APP_ENV", "development")
    return templates.TemplateResponse(request, "index.html", {"env": env})

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
