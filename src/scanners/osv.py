import httpx

from src.scanners.models import Vulnerability

OSV_API_URL = "https://api.osv.dev/v1/query"

def query_vulnerabilities(package_name: str, version: str | None, ecosystem: str = "PyPI") -> list[Vulnerability]:
    """Query OSV API for vulnerabilities in a package."""
    
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    
    if version:
        payload["version"] = version
    
    try:
        response = httpx.post(OSV_API_URL, json=payload, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        
        return parse_vulnerabilities(data)
    
    except httpx.HTTPError as e:
        print(f"Error querying OSV for {package_name}: {e}")
        return []

def parse_vulnerabilities(data: dict) -> list[Vulnerability]:
    """Parse OSV API response into Vulnerability objects."""
    vulnerabilities = []
    
    for vuln in data.get("vulns", []):
        severity = extract_severity(vuln)
        
        vulnerabilities.append(Vulnerability(
            id=vuln.get("id", "Unknown"),
            summary=vuln.get("summary", "No summary available"),
            severity=severity,
            details=vuln.get("details")
        ))
    
    return vulnerabilities

def extract_severity(vuln: dict) -> str | None:
    """Extract severity from vulnerability data."""
    severity_list = vuln.get("severity", [])
    if severity_list:
        return severity_list[0].get("score", None)
    
    db_specific = vuln.get("database_specific", {})
    if "severity" in db_specific:
        return db_specific["severity"]
    
    return None