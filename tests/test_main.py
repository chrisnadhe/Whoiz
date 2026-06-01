import pytest
from fastapi.testclient import TestClient
from app.main import app

# Sample mock data
mock_dns_records = {
    "A": {"records": [{"value": "192.168.1.1", "ttl": 300}], "error": None},
    "AAAA": {"records": [], "error": None},
    "MX": {"records": [{"value": "10 mail.google.com"}], "error": None},
    "TXT": {"records": [{"value": "v=spf1 include:_spf.google.com ~all"}], "error": None},
    "NS": {"records": [{"value": "ns1.google.com"}], "error": None},
    "CNAME": {"records": [], "error": None},
}

mock_whois_domain = {
    "type": "domain",
    "success": True,
    "summary": {
        "domain": "google.com",
        "registrar": "MarkMonitor Inc.",
        "creation_date": "1997-09-15 04:00:00",
        "expiration_date": "2028-09-13 04:00:00",
        "updated_date": "2019-09-09 15:39:04",
        "nameservers": "ns1.google.com",
        "status": "clientDeleteProhibited"
    },
    "raw": "Mock WHOIS domain raw text info"
}

mock_whois_ip = {
    "type": "ip",
    "success": True,
    "summary": {
        "ip": "8.8.8.8",
        "cidr": "8.8.8.0/24",
        "net_name": "LVLT-ORG-8-8-8",
        "asn": "AS15169",
        "asn_desc": "GOOGLE",
        "country": "US",
        "description": "Google LLC"
    },
    "raw": "Mock WHOIS IP raw text info"
}

mock_asn_details = {
    "success": True,
    "type": "asn",
    "asn": "15169",
    "country": "US",
    "registry": "arise",
    "allocated": "1997-09-15",
    "name": "GOOGLE",
    "ip": "-",
    "prefix": "-"
}

@pytest.fixture(autouse=True)
def mock_network_calls(monkeypatch):
    # Mock references inside app.main namespace
    monkeypatch.setattr("app.main.query_dns_records", lambda domain, resolver_ip=None, record_types=None: mock_dns_records)
    monkeypatch.setattr("app.main.query_reverse_dns", lambda ip, resolver_ip=None: "dns.google")
    monkeypatch.setattr("app.main.query_asn_details", lambda query_input: mock_asn_details)
    
    async def mock_async_query(*args, **kwargs):
        return {
            "success": True,
            "values": ["192.168.1.1"],
            "ttl": 300,
            "latency": 45.2,
            "error": None
        }
    monkeypatch.setattr("app.main.async_query_dns_record", mock_async_query)
    
    def mock_get_whois_data(query):
        from app.whois_utils import is_ip_address, clean_query
        q = clean_query(query)
        if is_ip_address(q):
            return mock_whois_ip
        return mock_whois_domain
    monkeypatch.setattr("app.main.get_whois_data", mock_get_whois_data)


client = TestClient(app)

# 1. Base Shell Layout
def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Whoiz" in response.text
    assert "<!DOCTYPE html>" in response.text
    assert "sidebar-desktop" in response.text

# 2. Inspector Feature
def test_inspector_page_non_htmx():
    response = client.get("/inspector")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "Domain & IP Inspector" in response.text
    assert "sidebar-desktop" in response.text

def test_inspector_page_htmx():
    response = client.get("/inspector", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "Domain & IP Inspector" in response.text
    assert "sidebar-desktop" not in response.text

def test_inspector_lookup_domain():
    response = client.post("/lookup", data={"query": "google.com", "resolver": "system"})
    assert response.status_code == 200
    assert "google.com" in response.text
    assert "DNS Records" in response.text
    assert "WHOIS Data" in response.text
    # Check that our mock details are inside the html response
    assert "MarkMonitor Inc." in response.text
    assert "ns1.google.com" in response.text

def test_inspector_lookup_ip():
    response = client.post("/lookup", data={"query": "8.8.8.8", "resolver": "system"})
    assert response.status_code == 200
    assert "8.8.8.8" in response.text
    assert "dns.google" in response.text
    assert "WHOIS Data" in response.text
    assert "LVLT-ORG-8-8-8" in response.text
    assert "AS15169" in response.text

# 3. DNS Propagation
def test_propagation_page_non_htmx():
    response = client.get("/propagation")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "DNS Propagation" in response.text

def test_propagation_page_htmx():
    response = client.get("/propagation", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "Global DNS Propagation" in response.text

def test_propagation_check():
    response = client.post("/propagation/check", data={"domain": "google.com", "record_type": "A"})
    assert response.status_code == 200
    assert "google.com" in response.text
    assert "Record" in response.text
    assert "Status" in response.text
    assert "Latency" in response.text

# 4. ASN Lookup
def test_asn_page_non_htmx():
    response = client.get("/asn")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "ASN Lookup" in response.text

def test_asn_page_htmx():
    response = client.get("/asn", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "ASN Lookup" in response.text

def test_asn_lookup_number():
    response = client.post("/asn/lookup", data={"query": "15169"})
    assert response.status_code == 200
    assert "15169" in response.text
    assert "GOOGLE" in response.text
    assert "US" in response.text

def test_asn_lookup_ip():
    response = client.post("/asn/lookup", data={"query": "8.8.8.8"})
    assert response.status_code == 200
    assert "15169" in response.text
    assert "GOOGLE" in response.text
    assert "US" in response.text

# 5. What is my IP
def test_my_ip_page_non_htmx():
    response = client.get("/my-ip")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "What is My IP?" in response.text

def test_my_ip_page_htmx():
    response = client.get("/my-ip", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "What is My IP?" in response.text

# 6. CIDR Calculator
def test_cidr_page_non_htmx():
    response = client.get("/cidr")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "CIDR Calculator" in response.text

def test_cidr_page_htmx():
    response = client.get("/cidr", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "CIDR Subnet Calculator" in response.text

def test_cidr_calculate():
    response = client.post("/cidr/calculate", data={"query": "192.168.1.0/24"})
    assert response.status_code == 200
    assert "192.168.1.0/24" in response.text
    assert "Subnet Mask" in response.text
    assert "255.255.255.0" in response.text
    assert "192.168.1.1" in response.text
    assert "192.168.1.254" in response.text
    assert "254" in response.text

# 7. MAC Address Lookup
def test_mac_page_non_htmx():
    response = client.get("/mac")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "MAC OUI Lookup" in response.text

def test_mac_page_htmx():
    response = client.get("/mac", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "MAC OUI Lookup" in response.text

def test_mac_lookup():
    response = client.post("/mac/lookup", data={"query": "00:00:0c:11:22:33"})
    assert response.status_code == 200
    assert "00:00:0C" in response.text.upper()  # Cisco system prefix
    assert "Cisco Systems" in response.text
    assert "OUI Prefix (Matched)" in response.text

# 8. QR Code Generator
def test_qr_page_non_htmx():
    response = client.get("/qr")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "QR Code Generator" in response.text

def test_qr_page_htmx():
    response = client.get("/qr", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "QR Code Generator" in response.text
    assert "QRious" in response.text

# 9. Password Generator
def test_password_page_non_htmx():
    response = client.get("/password")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert "Secure Password Generator" in response.text

def test_password_page_htmx():
    response = client.get("/password", headers={"hx-request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "Secure Password Generator" in response.text

def test_password_generate():
    response = client.post("/password/generate", data={
        "length": "24",
        "use_upper": "true",
        "use_lower": "true",
        "use_nums": "true",
        "use_syms": "true"
    })
    assert response.status_code == 200
    assert "Tingkat Keamanan" in response.text
    assert "Bits" in response.text
    assert "Strength" in response.text
