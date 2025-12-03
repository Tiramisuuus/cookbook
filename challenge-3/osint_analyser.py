#!/usr/bin/env python3
"""
osint_analyzer.py

Analyse les données produites par osint_collector.py (version simple) et calcule
un niveau de risque + un résumé pour aider à rédiger le rapport.

Usage :
    python3 osint_analyzer.py --input resultat_simple_shodan.json --out analysis.json
"""

import argparse
import json
from datetime import datetime
from typing import Any, Dict, List, Set


def load_collector_output(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_ips(data: Dict[str, Any]) -> Set[str]:
    meta = data.get("meta", {}) or {}
    ips = meta.get("ips", []) or []
    return set(ips)


def analyze_shodan(shodan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Récupère quelques infos utiles :
    - nombre d'IP trouvées dans Shodan
    - nombre total de services/ports vus
    - nombre d'hôtes avec vulnérabilités listées
    """
    if not isinstance(shodan_data, dict):
        return {
            "hosts_count": 0,
            "services_count": 0,
            "vuln_hosts_count": 0,
        }

    # Cas où Shodan pas utilisé
    if "info" in shodan_data and isinstance(shodan_data.get("info"), str):
        return {
            "hosts_count": 0,
            "services_count": 0,
            "vuln_hosts_count": 0,
            "info": shodan_data["info"],
        }

    hosts_count = 0
    services_count = 0
    vuln_hosts_count = 0

    for ip, host in shodan_data.items():
        if not isinstance(host, dict):
            continue
        hosts_count += 1

        data_list = host.get("data")
        if isinstance(data_list, list):
            services_count += len(data_list)

        vulns = host.get("vulns") or host.get("vulnerabilities")
        if vulns:
            vuln_hosts_count += 1

    return {
        "hosts_count": hosts_count,
        "services_count": services_count,
        "vuln_hosts_count": vuln_hosts_count,
    }


def compute_risk(ips: Set[str], shodan_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score très simple : on se base sur :
    - la surface (nombre d'IP)
    - le nombre de services visibles
    - la présence ou non de vulnérabilités dans Shodan
    """
    score = 0
    reasons: List[str] = []

    ip_count = len(ips)
    hosts_count = shodan_info.get("hosts_count", 0)
    services_count = shodan_info.get("services_count", 0)
    vuln_hosts_count = shodan_info.get("vuln_hosts_count", 0)

    if ip_count == 0:
        reasons.append("Aucune IP résolue pour le domaine (surface exposée très faible).")
    else:
        reasons.append(f"{ip_count} IP(s) associée(s) au domaine.")
        if ip_count > 5:
            score += 1
            reasons.append("Surface d'attaque modérément large (plus de 5 IP).")

    if hosts_count > 0:
        score += 1
        reasons.append(f"{hosts_count} hôte(s) trouvé(s) dans Shodan.")
    else:
        reasons.append("Aucun hôte trouvé dans Shodan ou Shodan non utilisé.")

    if services_count > 0:
        score += 1
        reasons.append(f"{services_count} service(s)/port(s) visible(s) dans Shodan.")

    if vuln_hosts_count > 0:
        score += 3
        reasons.append(
            f"Shodan signale des vulnérabilités sur {vuln_hosts_count} hôte(s)."
        )

    # Mapping score -> niveau
    if score <= 1:
        level = "faible"
    elif score <= 3:
        level = "moyen"
    elif score <= 5:
        level = "élevé"
    else:
        level = "critique"

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "details": {
            "ip_count": ip_count,
            "shodan_hosts_count": hosts_count,
            "shodan_services_count": services_count,
            "shodan_vuln_hosts_count": vuln_hosts_count,
        },
    }


def build_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    domain = data.get("meta", {}).get("domain", "unknown")
    collector_ts = data.get("meta", {}).get("timestamp_utc")

    ips = extract_ips(data)
    shodan_data = data.get("shodan", {}) or {}
    shodan_info = analyze_shodan(shodan_data)

    risk = compute_risk(ips, shodan_info)

    analysis = {
        "summary": {
            "domain": domain,
            "collector_timestamp_utc": collector_ts,
            "analysis_timestamp_utc": datetime.utcnow().isoformat() + "Z",
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
        },
        "reasons": risk["reasons"],
        "metrics": risk["details"],
        "entities": {
            "ips": sorted(ips),
            "shodan_raw": shodan_data,  # pour aller chercher des détails précis au besoin
        },
    }
    return analysis


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse les données OSINT collectées et calcule un niveau de risque."
    )
    parser.add_argument("--input", required=True, help="Fichier JSON produit par osint_collector.py")
    parser.add_argument("--out", default="-", help="Fichier de sortie JSON (ou - pour stdout)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    collector_data = load_collector_output(args.input)
    analysis = build_analysis(collector_data)

    payload = json.dumps(analysis, indent=2, ensure_ascii=False)
    if args.out == "-" or not args.out:
        print(payload)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        print(f"Analyse écrite dans {args.out}")


if __name__ == "__main__":
    main()
