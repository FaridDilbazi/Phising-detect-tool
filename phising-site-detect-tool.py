import re
import requests   
from urllib.parse import urlparse
from typing import Dict, Tuple

def validate_url(url: str) -> Tuple[bool, Dict[str, any]]:
    details = {
        "valid_format": False,
        "accessible": False,
        "ssl_cert": False,
        "suspicious_patterns": [],
        "redirect_count": 0
    }
    
    try:
        parsed = urlparse(url)
        if all([parsed.scheme, parsed.netloc]):
            details["valid_format"] = True
    except Exception:
        return False, details

    suspicious = [
        r"paypal.*\.com(?!\.paypal\.com)",  
        r".*\.com-[A-Za-z0-9]",  
        r".*@.*",  
        r".*[0-9]{10,}.*"  
    ]
    
    for pattern in suspicious:
        if re.match(pattern, url):
            details["suspicious_patterns"].append(pattern)

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        details["accessible"] = response.status_code == 200
        details["ssl_cert"] = url.startswith("https")
        details["redirect_count"] = len(response.history)
    except requests.exceptions.RequestException:
        pass

    is_valid = (details["valid_format"] and 
                details["accessible"] and 
                not details["suspicious_patterns"])
    
    return is_valid, details

while True:
    url = input("Enter a URL (if you want to quit enter the 'quit'): ")
    
    if url.lower() == 'quit':
        print("Closing program...")
        break
        
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    print(f"\nChecking URL: {url}")
    is_valid, details = validate_url(url)
    
    print(f"\nResults:")
    print(f"Overall validity: {'Valid' if is_valid else 'Invalid'}")
    print("\nDetailed checks:")
    print(f"✓ Format: {details['valid_format']}")
    print(f"✓ Accessibility: {details['accessible']}")
    print(f"✓ SSL Certificate: {details['ssl_cert']}")
    print(f"✓ Redirect count: {details['redirect_count']}")
    
    if details['suspicious_patterns']:
        print("\n Warning: Suspicious patterns detected!")
        for pattern in details['suspicious_patterns']:
            print(f"- Matching pattern: {pattern}")
