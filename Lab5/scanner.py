import requests

# Target setup (Juice Shop running on port 3000)
base_url = "http://localhost:3000"
endpoints = ["/", "/rest/products/search", "/login"]

def run_scanner():
    print(f"Starting Reconnaissance on {base_url}")
    for route in endpoints:
        url = f"{base_url}{route}"
        try:
            response = requests.get(url, timeout=5)
            print(f"[+] Endpoint: {route}")
            print(f"    Method: GET | Status: {response.status_code} | Length: {len(response.text)}")
            
            security_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"]
            for header in security_headers:
                if header not in response.headers:
                    print(f"    [!] Low Severity: Missing {header}")
                    
        except requests.exceptions.RequestException as e:
            print(f"[-] Connection error at {route}: {e}")

if __name__ == "__main__":
    run_scanner()
