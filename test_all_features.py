import urllib.request
import urllib.parse
import sys

BASE_URL = "http://127.0.0.1:8000"

def make_request(path, method="GET", form_data=None, is_htmx=False):
    url = f"{BASE_URL}{path}"
    headers = {}
    if is_htmx:
        headers["hx-request"] = "true"
    
    data = None
    if form_data:
        data = urllib.parse.urlencode(form_data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.getcode(), response.read().decode("utf-8")
    except Exception as e:
        return 500, f"Error: {str(e)}"

def verify_contains(html, keywords):
    found = [k for k in keywords if k in html]
    return len(found) == len(keywords), found

def run_tests():
    print("=" * 60)
    print("    WHOIZ APP - FULL FEATURE INTEGRATION TESTING SUITE    ")
    print("=" * 60)
    
    all_passed = True
    
    # List of test cases: (name, path, method, form_data, is_htmx, expected_keywords, unexpected_keywords)
    tests = [
        # 1. Base Shell Layout
        (
            "Base Shell Layout (Non-HTMX GET /)",
            "/", "GET", None, False,
            ["Whoiz", "<!DOCTYPE html>", "sidebar-desktop", "Network Tools"],
            []
        ),
        
        # 2. Inspector Feature
        (
            "Inspector Page Page Shell (Non-HTMX GET /inspector)",
            "/inspector", "GET", None, False,
            ["<!DOCTYPE html>", "Domain & IP Inspector", "Periksa DNS record"],
            []
        ),
        (
            "Inspector Page Fragment (HTMX GET /inspector)",
            "/inspector", "GET", None, True,
            ["Domain & IP Inspector", "Periksa DNS record"],
            ["<!DOCTYPE html>", "sidebar-desktop"] # Fragment should not contain shell layout
        ),
        (
            "Inspector Domain Lookup (POST /lookup)",
            "/lookup", "POST", {"query": "google.com", "resolver": "system"}, True,
            ["google.com", "DNS Records", "WHOIS Data"],
            ["<!DOCTYPE html>"]
        ),
        (
            "Inspector IP Lookup (POST /lookup)",
            "/lookup", "POST", {"query": "8.8.8.8", "resolver": "system"}, True,
            ["8.8.8.8", "Reverse DNS (PTR)", "WHOIS Data"],
            ["<!DOCTYPE html>"]
        ),
        
        # 3. DNS Propagation
        (
            "DNS Propagation Shell (Non-HTMX GET /propagation)",
            "/propagation", "GET", None, False,
            ["<!DOCTYPE html>", "DNS Propagation", "Global DNS Propagation"],
            []
        ),
        (
            "DNS Propagation Fragment (HTMX GET /propagation)",
            "/propagation", "GET", None, True,
            ["Global DNS Propagation", "prop-query"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        (
            "DNS Propagation Check (POST /propagation/check)",
            "/propagation/check", "POST", {"domain": "google.com", "record_type": "A"}, True,
            ["google.com", "Record", "Status", "Latency"],
            ["<!DOCTYPE html>"]
        ),
        
        # 4. ASN Lookup
        (
            "ASN Lookup Shell (Non-HTMX GET /asn)",
            "/asn", "GET", None, False,
            ["<!DOCTYPE html>", "ASN Lookup", "Masukkan Nomor AS"],
            []
        ),
        (
            "ASN Lookup Fragment (HTMX GET /asn)",
            "/asn", "GET", None, True,
            ["ASN Lookup", "Masukkan Nomor AS"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        (
            "ASN Lookup Query by Number (POST /asn/lookup)",
            "/asn/lookup", "POST", {"query": "15169"}, True,
            ["15169", "GOOGLE", "US"],
            ["<!DOCTYPE html>"]
        ),
        (
            "ASN Lookup Query by IP (POST /asn/lookup)",
            "/asn/lookup", "POST", {"query": "8.8.8.8"}, True,
            ["15169", "GOOGLE", "US"],
            ["<!DOCTYPE html>"]
        ),
        
        # 5. What is my IP
        (
            "What is my IP Shell (Non-HTMX GET /my-ip)",
            "/my-ip", "GET", None, False,
            ["<!DOCTYPE html>", "What is My IP?", "Protocol", "Browser User Agent"],
            []
        ),
        (
            "What is my IP Fragment (HTMX GET /my-ip)",
            "/my-ip", "GET", None, True,
            ["What is My IP?", "Protocol", "Browser User Agent"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        
        # 6. CIDR Calculator
        (
            "CIDR Calculator Shell (Non-HTMX GET /cidr)",
            "/cidr", "GET", None, False,
            ["<!DOCTYPE html>", "CIDR Calculator", "IP Address / CIDR Block"],
            []
        ),
        (
            "CIDR Calculator Fragment (HTMX GET /cidr)",
            "/cidr", "GET", None, True,
            ["CIDR Subnet Calculator", "IP Address / CIDR Block"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        (
            "CIDR Calculate IPv4 (POST /cidr/calculate)",
            "/cidr/calculate", "POST", {"query": "192.168.1.0/24"}, True,
            ["192.168.1.0/24", "Subnet Mask", "Wildcard Mask", "255.255.255.0", "192.168.1.1", "192.168.1.254", "254"],
            ["<!DOCTYPE html>"]
        ),
        
        # 7. MAC Address Lookup
        (
            "MAC Lookup Shell (Non-HTMX GET /mac)",
            "/mac", "GET", None, False,
            ["<!DOCTYPE html>", "MAC OUI Lookup", "MAC Address"],
            []
        ),
        (
            "MAC Lookup Fragment (HTMX GET /mac)",
            "/mac", "GET", None, True,
            ["MAC OUI Lookup", "MAC Address"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        (
            "MAC Lookup OUI Lookup (POST /mac/lookup)",
            "/mac/lookup", "POST", {"query": "00:00:0c:11:22:33"}, True,
            ["00:00:0C", "Cisco Systems", "Valid OUI (3 Bytes)"],
            ["<!DOCTYPE html>"]
        ),
        
        # 8. QR Code Generator
        (
            "QR Generator Shell (Non-HTMX GET /qr)",
            "/qr", "GET", None, False,
            ["<!DOCTYPE html>", "QR Code Generator", "qrious", "Live Preview"],
            []
        ),
        (
            "QR Generator Fragment (HTMX GET /qr)",
            "/qr", "GET", None, True,
            ["QR Code Generator", "qrious", "Live Preview"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        
        # 9. Password Generator
        (
            "Password Gen Shell (Non-HTMX GET /password)",
            "/password", "GET", None, False,
            ["<!DOCTYPE html>", "Secure Password Generator", "Panjang Karakter"],
            []
        ),
        (
            "Password Gen Fragment (HTMX GET /password)",
            "/password", "GET", None, True,
            ["Secure Password Generator", "Panjang Karakter"],
            ["<!DOCTYPE html>", "sidebar-desktop"]
        ),
        (
            "Password Generate Action (POST /password/generate)",
            "/password/generate", "POST", {
                "length": "24",
                "use_upper": "true",
                "use_lower": "true",
                "use_nums": "true",
                "use_syms": "true"
            }, True,
            ["Hasil Kata Sandi", "Bits", "Strength", "Copy"],
            ["<!DOCTYPE html>"]
        )
    ]
    
    for idx, (name, path, method, form_data, is_htmx, expected, unexpected) in enumerate(tests, 1):
        print(f"[{idx:02d}] {name:<50} ... ", end="")
        code, html = make_request(path, method, form_data, is_htmx)
        
        if code != 200:
            print(f"\033[91mFAILED\033[0m (HTTP {code})")
            print(f"    Error detail: {html[:200]}")
            all_passed = False
            continue
        
        # Validate expected keywords
        passed_exp, found_exp = verify_contains(html, expected)
        # Validate unexpected keywords
        failed_unexp = [u for u in unexpected if u in html]
        
        if passed_exp and not failed_unexp:
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91mFAILED\033[0m")
            if not passed_exp:
                missing = [e for e in expected if e not in found_exp]
                print(f"    Missing keywords: {missing}")
            if failed_unexp:
                print(f"    Found unexpected keywords (HTMX fragment pollution): {failed_unexp}")
            all_passed = False
            
    print("=" * 60)
    if all_passed:
        print("\033[92mSUCCESS: All dashboard features and layout rendering are verified!\033[0m")
        sys.exit(0)
    else:
        print("\033[91mFAILURE: One or more test checks failed. Review logs above.\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
