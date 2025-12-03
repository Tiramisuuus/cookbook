#!/usr/bin/env python3
"""
osint_collector.py

Collecte OSINT passive et simple autour d'un domaine :
- DNS (A, AAAA)
- WHOIS (si la commande 'whois' existe)
- Shodan (si clé API fournie)

Usage :
    python3 osint_collector.py --domain exemple.com --out output.json
    python3 osint_collector.py --domain exemple.com --shodan-key VOTRE_CLE --out output.json
"""

import argparse
import json
import socket
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import requests

# Option : masquer le warning NotOpenSSLWarning de urllib3 sur macOS
try:
    import warnings
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except Exception:
    pass

USER_AGENT = "DarkWatch-OSINT-Collector-Simple/1.0"


# ---------------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------------

def run_command(cmd: List[str], timeout: int = 20) -> str:
    """Exécute une commande système et renvoie stdout (ou un message d'erreur)."""
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        return completed.stdout
    except FileNotFoundError:
        return f"ERROR: command not found: {cmd[0]}"
    except Exception as e:
        return f"ERROR: {e}"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def collect_dns(domain: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {"A": [], "AAAA": []}

    # A records
    try:
        _, _, addrs = socket.gethostbyname_ex(domain)
        data["A"] = sorted(set(addrs))
    except Exception:
        data["A"] = []

    # AAAA records (best effort)
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        v6 = {i[4][0] for i in infos if ":" in i[4][0]}
        data["AAAA"] = sorted(v6)
    except Exception:
        data["AAAA"] = []

    return data


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def collect_whois(domain: str) -> Dict[str, Any]:
    """WHOIS simple via binaire 'whois' si disponible."""
    out = run_command(["whois", domain], timeout=30)
    return {"raw": out}


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def collect_shodan_for_ips(ips: List[str], shodan_key: Optional[str]) -> Dict[str, Any]:
    """
    Interroge Shodan pour chaque IP (limité à 5 IP pour rester rapide).
    Si aucune clé fournie, renvoie juste une info.
    """
    if not shodan_key:
        return {"info": "No Shodan API key provided, skipping Shodan lookups."}

    # On limite volontairement à 5 IP max pour que ça reste très rapide.
    ips = ips[:5]

    base_url = "https://api.shodan.io/shodan/host/"
    headers = {"User-Agent": USER_AGENT}
    results: Dict[str, Any] = {}

    for ip in ips:
        url = base_url + ip
        params = {"key": shodan_key}
        try:
            r = requests.get(url, params=params, headers=headers, timeout=20)
            if r.status_code == 404:
                results[ip] = {"found": False}
            elif r.status_code != 200:
                results[ip] = {
                    "error": f"HTTP {r.status_code}",
                    "body": r.text[:500],
                }
            else:
                results[ip] = r.json()
        except Exception as e:
            results[ip] = {"error": str(e)}

    return results


# ---------------------------------------------------------------------------
# Collecte principale
# ---------------------------------------------------------------------------

def collect_all(domain: str, shodan_key: Optional[str]) -> Dict[str, Any]:
    timestamp = datetime.utcnow().isoformat() + "Z"

    dns_data = collect_dns(domain)
    whois_data = collect_whois(domain)

    ips: Set[str] = set(dns_data.get("A", []) + dns_data.get("AAAA", []))
    ips_list = sorted(ips)

    shodan_data = collect_shodan_for_ips(ips_list, shodan_key) if ips_list else {
        "info": "No IPs resolved for this domain, Shodan skipped."
    }

    result: Dict[str, Any] = {
        "meta": {
            "domain": domain,
            "timestamp_utc": timestamp,
            "ips": ips_list,
            "tool": "DarkWatch OSINT Collector (simple)",
        },
        "dns": dns_data,
        "whois": whois_data,
        "shodan": shodan_data,
    }
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OSINT Collector simple (DNS, WHOIS, Shodan)."
    )
    parser.add_argument("--domain", required=True, help="Nom de domaine (ex: exemple.com)")
    parser.add_argument("--shodan-key", help="Clé API Shodan (optionnelle)")
    parser.add_argument("--out", default="-", help="Fichier de sortie JSON (ou - pour stdout)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data = collect_all(args.domain, args.shodan_key)

    payload = json.dumps(data, indent=2, ensure_ascii=False)
    if args.out == "-" or args.out == "":
        print(payload)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"Résultats écrits dans {args.out}")


if __name__ == "__main__":
    main()
