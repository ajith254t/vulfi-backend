import json
import re
import dns.resolver
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

# ---------------- APP SETUP ----------------
app = FastAPI(title="VULFI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to "*" in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- WEBSITE SCAN MODELS ----------------
class ScanRequest(BaseModel):
    url: HttpUrl


class Vulnerability(BaseModel):
    name: str
    severity: str
    description: str


class ScanResponse(BaseModel):
    target: str
    total_vulnerabilities: int
    rating: int
    status: str
    vulnerabilities: List[Vulnerability]


# ---------------- DEVICE SCAN MODELS ----------------
class DeviceScanRequest(BaseModel):
    device_type: str
    os_version: str
    extra: Optional[str] = None


class DeviceFinding(BaseModel):
    title: str
    severity: str
    description: str


class DeviceScanResponse(BaseModel):
    device: str
    rating: int
    risk: str
    findings: List[DeviceFinding]
    recommendations: List[str]


# ---------------- EMAIL SCAN MODELS ----------------
class EmailScanRequest(BaseModel):
    email:EmailStr


class EmailScanResponse(BaseModel):
    email: str
    rating: int
    risk: str
    findings: List
    recommendations: List


# ---------------- SCORING LOGIC ----------------
def calculate_rating(vulnerabilities: List[Vulnerability]) -> int:
    severity_weights = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1
    }

    score = 0
    critical_found = False

    for v in vulnerabilities:
        score += severity_weights.get(v.severity, 0)
        if v.severity == "Critical":
            critical_found = True

    if critical_found:
        return 1
    elif score > 20:
        return 2
    elif score > 10:
        return 3
    elif score > 3:
        return 4
    else:
        return 5


# ---------------- SSL CHECK ----------------
def check_ssl(url: str):
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {
            "https": False,
            "certificate_valid": False,
            "expires_in_days": None,
            "issue": "HTTPS not enabled"
        }

    hostname = parsed.hostname
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        days_left = (expiry_date - datetime.utcnow()).days

        return {
            "https": True,
            "certificate_valid": days_left > 0,
            "expires_in_days": days_left,
            "issue": None if days_left > 0 else "Certificate expired"
        }

    except Exception:
        return {
            "https": True,
            "certificate_valid": False,
            "expires_in_days": None,
            "issue": "SSL check failed"
        }


# ---------------- HTTP REDIRECT CHECK ----------------
def check_http_redirect(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "redirects_to_https": False,
            "issue": "Invalid hostname"
        }

    http_url = f"http://{hostname}"

    try:
        response = requests.get(http_url, timeout=5, allow_redirects=False)

        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                return {"redirects_to_https": True, "issue": None}

        return {
            "redirects_to_https": False,
            "issue": "HTTP does not redirect to HTTPS"
        }

    except requests.RequestException:
        return {
            "redirects_to_https": False,
            "issue": "HTTP redirect check failed"
        }


# ---------------- DEVICE ANALYSIS LOGIC ----------------
def analyze_device(device_type: str, os_version: str, extra: Optional[str]):
    findings = []
    recommendations = []
    rating = 5

    patch = None
    brand = "unknown"

    if extra:
        try:
            data = json.loads(extra)
            patch = data.get("patch")
            brand = data.get("brand", "unknown").lower()
        except Exception:
            pass

    if device_type == "android":
        version = int(os_version.replace("android", ""))

        trusted_brands = ["google", "samsung", "oneplus"]
        slow_brands = ["huawei", "other"]

        if version <= 11:
            rating = 2
            findings.append(DeviceFinding(
                title="Outdated Android Version",
                severity="High",
                description="This Android version no longer receives security updates."
            ))
            recommendations.append("Upgrade to Android 13 or newer.")

        elif version == 12:
            rating = 3
            findings.append(DeviceFinding(
                title="Android Version Aging",
                severity="Medium",
                description="Security support is limited."
            ))
            recommendations.append("Consider upgrading Android.")

        else:
            rating = 4
            recommendations.append("Keep Android security patches updated.")

        if brand in trusted_brands and rating < 5:
            rating += 1

        if brand in slow_brands and rating > 1:
            rating -= 1
            findings.append(DeviceFinding(
                title="Slow Security Updates",
                severity="Medium",
                description="Brand may delay security updates."
            ))

        if patch:
            recommendations.append("Install monthly Android security patches.")

        device_name = f"Android {version} ({brand.capitalize()})"

    elif device_type == "windows":
        device_name = f"Windows Device ({brand.capitalize()})"

        if "21H2" in os_version:
            rating = 2
            findings.append(DeviceFinding(
                title="Windows Version End of Support",
                severity="High",
                description="This version is no longer supported."
            ))
            recommendations.append("Upgrade Windows.")

        elif "22H2" in os_version:
            rating = 3
            recommendations.append("Plan Windows upgrade.")

        else:
            rating = 4
            recommendations.append("Keep Windows Update enabled.")

    elif device_type == "mac":
        device_name = "Apple Device"
        if os_version in ["monterey", "ios16"]:
            rating = 3
            findings.append(DeviceFinding(
                title="Limited Apple OS Support",
                severity="Medium",
                description="Limited security updates."
            ))
            recommendations.append("Upgrade Apple OS.")
        else:
            rating = 5
            recommendations.append("Keep Apple updates enabled.")

    else:
        device_name = "Unknown Device"
        rating = 3
        findings.append(DeviceFinding(
            title="Unknown Device Type",
            severity="Low",
            description="Device could not be identified."
        ))

    rating = max(1, min(5, rating))

    risk_map = {
        1: "Critical Risk",
        2: "High Risk",
        3: "Moderate Risk",
        4: "Low Risk",
        5: "Secure"
    }

    return {
        "device": device_name,
        "rating": rating,
        "risk": risk_map[rating],
        "findings": findings,
        "recommendations": recommendations
    }


# ---------------- EMAIL ANALYSIS LOGIC ----------------
def has_spf(domain):
    """Check if domain has a valid SPF record"""
    try:
        records = dns.resolver.resolve(domain, "TXT")
        for r in records:
            if "v=spf1" in str(r):
                return True
    except Exception:
        pass
    return False


def has_dmarc(domain):
    """Check if domain has a valid DMARC record"""
    try:
        records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in records:
            if "v=DMARC1" in str(r):
                return True
    except Exception:
        pass
    return False


def check_breach_exposure(email):
    """Placeholder for breach exposure check - requires API integration"""
    # This would integrate with services like Have I Been Pwned
    # Requires API key - use environment variables in production
    return False

def analyze_email(email: str):
    findings = []
    recommendations = []
    rating = 5

    # Validate email format
    if not email or "@" not in email:
        return {
            "email": email,
            "rating": 1,
            "risk": "Critical Risk",
            "findings": [{
                "title": "Invalid Email Format",
                "severity": "Critical",
                "description": "Email address format is invalid."
            }],
            "recommendations": ["Enter a valid email address."]
        }

    domain = email.split("@")[1]

    disposable_domains = [
        "tempmail.com", "10minutemail.com", "mailinator.com",
        "guerrillamail.com", "yopmail.com"
    ]

    if domain in disposable_domains:
        return {
            "email": email,
            "rating": 1,
            "risk": "Critical Risk",
            "findings": [{
                "title": "Disposable Email Address",
                "severity": "Critical",
                "description": "Disposable email detected."
            }],
            "recommendations": ["Avoid disposable email addresses."]
        }

    # SPF check
    if not has_spf(domain):
        rating -= 1
        findings.append({
            "title": "Missing SPF Record",
            "severity": "Medium",
            "description": "SPF record not found. Email spoofing is possible."
        })
        recommendations.append("Configure SPF to authorize sending mail servers.")

    # DMARC check
    if not has_dmarc(domain):
        rating -= 1
        findings.append({
            "title": "Missing DMARC Policy",
            "severity": "High",
            "description": "DMARC is not configured."
        })
        recommendations.append("Configure DMARC policy to protect your domain.")

    public_providers = [
        "gmail.com", "yahoo.com", "outlook.com",
        "hotmail.com", "icloud.com"
    ]

    if domain in public_providers:
        recommendations.append("Enable two-factor authentication (2FA).")
    else:
        recommendations.append("Ensure strong organizational email security policies.")

    rating = max(1, min(5, rating))

    risk_map = {
        1: "Critical Risk",
        2: "High Risk",
        3: "Moderate Risk",
        4: "Low Risk",
        5: "Secure"
    }

    return {
        "email": email,
        "rating": rating,
        "risk": risk_map[rating],
        "findings": findings,
        "recommendations": recommendations
    }




# ---------------- WEBSITE SCAN ENDPOINT ----------------
@app.post("/scan", response_model=ScanResponse)
def scan_website(request: ScanRequest):
    ssl_result = check_ssl(str(request.url))
    redirect_result = check_http_redirect(str(request.url))

    vulnerabilities: List[Vulnerability] = []

    if not ssl_result["https"]:
        vulnerabilities.append(Vulnerability(
            name="HTTPS Not Enabled",
            severity="Critical",
            description="Website does not use HTTPS."
        ))

    elif not ssl_result["certificate_valid"]:
        vulnerabilities.append(Vulnerability(
            name="Invalid SSL Certificate",
            severity="High",
            description="SSL certificate is invalid."
        ))

    if not redirect_result["redirects_to_https"]:
        vulnerabilities.append(Vulnerability(
            name="HTTP to HTTPS Redirect Missing",
            severity="High",
            description=redirect_result["issue"]
        ))

    rating = calculate_rating(vulnerabilities)

    status_map = {
        1: "Critical Risk",
        2: "High Risk",
        3: "Moderate Risk",
        4: "Low Risk",
        5: "Secure"
    }

    return ScanResponse(
        target=str(request.url),
        total_vulnerabilities=len(vulnerabilities),
        rating=rating,
        status=status_map[rating],
        vulnerabilities=vulnerabilities
    )


# ---------------- DEVICE SCAN ENDPOINT ----------------
@app.post("/device-scan", response_model=DeviceScanResponse)
def device_scan(request: DeviceScanRequest):
    result = analyze_device(
        request.device_type,
        request.os_version,
        request.extra
    )

    return DeviceScanResponse(**result)


# ---------------- EMAIL SCAN ENDPOINT ----------------
@app.post("/email-scan", response_model=EmailScanResponse)
def email_scan(request: EmailScanRequest):
    result = analyze_email(request.email)

    return EmailScanResponse(**result)

