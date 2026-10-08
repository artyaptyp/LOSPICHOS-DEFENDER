from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import requests
import socket
import ssl
import dns.resolver
import re
import ipaddress
import os
from datetime import datetime

app = FastAPI(title="Web Security Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


def normalize_url(url):
    value = url.strip()

    if not value:
        raise ValueError("URL vazia.")

    if re.search(r"\s", value):
        raise ValueError("Isso não parece um link válido: contém espaço.")

    if value.startswith(("http://", "https://")):
        candidate = value
    else:
        candidate = "https://" + value

    parsed = urlparse(candidate)
    host = parsed.hostname

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Isso não é um link válido. Use http:// ou https://")

    if not host:
        raise ValueError("URL inválida: não foi possível identificar o domínio.")

    if host not in ("localhost",) and "." not in host and not host.isdigit():
        raise ValueError("Isso não é um link válido: falta domínio ou extensão.")

    return candidate


def get_domain(url):
    parsed = urlparse(url)
    return parsed.hostname


def check_https(url):
    parsed = urlparse(url)

    return {
        "name": "HTTPS",
        "status": "clean" if parsed.scheme == "https" else "warning",
        "message": (
            "Conexão HTTPS detectada."
            if parsed.scheme == "https"
            else "O site não está usando HTTPS."
        )
    }


def check_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")

        ips = [answer.to_text() for answer in answers]

        return {
            "name": "DNS",
            "status": "clean",
            "message": f"Domínio resolvido para {', '.join(ips)}",
            "ips": ips
        }

    except Exception as e:
        return {
            "name": "DNS",
            "status": "danger",
            "message": "Não foi possível resolver o domínio."
        }


def check_ip(domain):
    try:
        ip = socket.gethostbyname(domain)

        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            status = "warning"
        else:
            status = "clean"

        return {
            "name": "IP",
            "status": status,
            "message": f"IP encontrado: {ip}"
        }

    except Exception:
        return {
            "name": "IP",
            "status": "danger",
            "message": "Não foi possível obter o IP."
        }


def check_ssl(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:

                certificate = secure_sock.getpeercert()

                expires = certificate.get("notAfter", "Desconhecido")

                return {
                    "name": "SSL/TLS",
                    "status": "clean",
                    "message": f"Certificado válido. Expiração: {expires}"
                }

    except Exception as e:
        return {
            "name": "SSL/TLS",
            "status": "danger",
            "message": "Não foi possível validar o certificado."
        }


def check_http(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 WebSecurityScanner/1.0"
            }
        )

        return {
            "name": "HTTP",
            "status": "clean",
            "message": f"HTTP {response.status_code} — {response.url}",
            "status_code": response.status_code,
            "final_url": response.url,
            "headers": dict(response.headers)
        }

    except Exception as e:
        return {
            "name": "HTTP",
            "status": "danger",
            "message": f"Falha ao acessar o site: {str(e)}"
        }


def check_security_headers(headers):
    required = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy"
    ]

    found = []
    missing = []

    lower_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    for header in required:
        if header in lower_headers:
            found.append(header)
        else:
            missing.append(header)

    if len(found) >= 4:
        status = "clean"
    elif len(found) >= 2:
        status = "warning"
    else:
        status = "warning"

    return {
        "name": "Security Headers",
        "status": status,
        "message": f"{len(found)}/{len(required)} headers de segurança encontrados.",
        "found": found,
        "missing": missing
    }


def heuristic_scan(url):
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "wallet",
        "signin",
        "confirm"
    ]

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    score = 0
    reasons = []

    if "@" in url:
        score += 25
        reasons.append("URL contém '@'.")

    if len(url) > 180:
        score += 10
        reasons.append("URL extremamente longa.")

    if domain.count("-") >= 4:
        score += 10
        reasons.append("Domínio possui muitos hífens.")

    if domain.count(".") >= 4:
        score += 10
        reasons.append("Domínio possui muitos subdomínios.")

    for word in suspicious_words:
        if word in domain.lower():
            score += 5
            reasons.append(f"Termo potencialmente suspeito: {word}")

    for tld in suspicious_tlds:
        if domain.lower().endswith(tld):
            score += 15
            reasons.append(f"TLD com histórico de abuso: {tld}")

    if score >= 40:
        status = "danger"
    elif score >= 15:
        status = "warning"
    else:
        status = "clean"

    return {
        "name": "Heuristic Analysis",
        "status": status,
        "score": min(score, 100),
        "message": (
            "Nenhum padrão suspeito importante encontrado."
            if not reasons
            else "Possíveis indicadores encontrados."
        ),
        "reasons": reasons
    }


def check_urlhaus(url):
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=10
        )

        data = response.json()

        if data.get("query_status") == "no_results":
            return {
                "name": "URLhaus",
                "status": "clean",
                "message": "URL não encontrada na base conhecida do URLhaus."
            }

        if data.get("query_status") == "ok":
            return {
                "name": "URLhaus",
                "status": "danger",
                "message": "URL encontrada na base do URLhaus.",
                "threat": data.get("threat"),
                "url_status": data.get("url_status")
            }

        return {
            "name": "URLhaus",
            "status": "warning",
            "message": "Não foi possível determinar a reputação."
        }

    except Exception:
        return {
            "name": "URLhaus",
            "status": "warning",
            "message": "Serviço temporariamente indisponível."
        }


def check_virustotal(url):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "name": "VirusTotal",
            "status": "warning",
            "message": "Configure a variável VT_API_KEY para ativar a verificação de reputação do VirusTotal.",
            "antivirus": [],
            "engines_count": 0
        }

    try:
        headers = {
            "x-apikey": api_key,
            "accept": "application/json"
        }

        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
            timeout=20
        )

        if submit_response.status_code == 429:
            return {
                "name": "VirusTotal",
                "status": "warning",
                "message": "O limite da API do VirusTotal foi atingido. Tente novamente mais tarde.",
                "antivirus": [],
                "engines_count": 0
            }

        if submit_response.status_code != 200:
            return {
                "name": "VirusTotal",
                "status": "warning",
                "message": "Não foi possível consultar o VirusTotal no momento.",
                "antivirus": [],
                "engines_count": 0
            }

        analysis_id = submit_response.json().get("data", {}).get("id")

        if not analysis_id:
            return {
                "name": "VirusTotal",
                "status": "warning",
                "message": "Resposta do VirusTotal sem identificador de análise.",
                "antivirus": [],
                "engines_count": 0
            }

        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=20
        )

        if analysis_response.status_code != 200:
            return {
                "name": "VirusTotal",
                "status": "warning",
                "message": "A análise do VirusTotal ainda não está disponível.",
                "antivirus": [],
                "engines_count": 0
            }

        analysis_data = analysis_response.json().get("data", {})
        attributes = analysis_data.get("attributes", {})
        stats = attributes.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        engine_results = attributes.get("results", {})
        antivirus = [
            {
                "engine": engine_name,
                "result": result.get("result", "unknown"),
                "category": result.get("category", "unknown")
            }
            for engine_name, result in engine_results.items()
        ]
        antivirus.sort(key=lambda item: item["engine"].lower())

        if malicious > 0 or suspicious > 0:
            status = "danger" if malicious > 0 else "warning"
            detections = [
                {"engine": engine_name, "result": result.get("result")}
                for engine_name, result in engine_results.items()
                if result.get("result") in ("malicious", "suspicious")
            ]
            top_detections = detections[:5]

            return {
                "name": "VirusTotal",
                "status": status,
                "message": f"URL marcada por {malicious + suspicious} motores do VirusTotal.",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "top_detections": top_detections,
                "antivirus": antivirus,
                "engines_count": len(antivirus)
            }

        return {
            "name": "VirusTotal",
            "status": "clean",
            "message": f"Nenhuma detecção maliciosa foi encontrada pelo VirusTotal ({harmless} seguros, {undetected} não avaliados).",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "antivirus": antivirus,
            "engines_count": len(antivirus)
        }

    except Exception as e:
        return {
            "name": "VirusTotal",
            "status": "warning",
            "message": f"Erro ao consultar o VirusTotal: {str(e)}",
            "antivirus": [],
            "engines_count": 0
        }


@app.post("/scan")
def scan(request: ScanRequest):

    try:
        url = normalize_url(request.url)
        parsed = urlparse(url)

        if not parsed.hostname:
            return {
                "success": False,
                "error": "URL inválida.",
                "is_url": False
            }

        domain = parsed.hostname

    except ValueError as exc:
        return {
            "success": False,
            "error": str(exc),
            "is_url": False
        }

    except Exception:
        return {
            "success": False,
            "error": "URL inválida.",
            "is_url": False
        }

    results = []

    https_result = check_https(url)
    results.append(https_result)

    dns_result = check_dns(domain)
    results.append(dns_result)

    ip_result = check_ip(domain)
    results.append(ip_result)

    ssl_result = check_ssl(domain)
    results.append(ssl_result)

    http_result = check_http(url)
    results.append(http_result)

    if http_result.get("headers"):
        headers_result = check_security_headers(
            http_result["headers"]
        )
        results.append(headers_result)

    heuristic_result = heuristic_scan(url)
    results.append(heuristic_result)

    virustotal_result = check_virustotal(url)
    results.append(virustotal_result)

    urlhaus_result = check_urlhaus(url)
    results.append(urlhaus_result)

    dangers = sum(
        1 for result in results
        if result.get("status") == "danger"
    )

    warnings = sum(
        1 for result in results
        if result.get("status") == "warning"
    )

    total = len(results)

    if dangers > 0:
        overall = "danger"
    elif warnings > 0:
        overall = "warning"
    else:
        overall = "clean"

    return {
        "success": True,
        "url": url,
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "overall": overall,
            "danger": dangers,
            "warnings": warnings,
            "clean": total - dangers - warnings,
            "total": total
        },
        "results": results
    }