from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import traceback
import nmap
import requests
import re

print("Flask app is starting...")

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

@app.route('/')
def home():
    return render_template('new.html')  # this loads your frontend

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.json
        ip = data.get('target')
        options = data.get('options', {})
        print(f"Received scan request for IP: {ip}")
        print(f"Scan options: {options}")

        # Nmap scan
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sV')

        results = {
            "ip": ip,
            "openPorts": [],
            "services": [],
            "weakConfigurations": [],
            "cves": []
        }

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service = nm[host][proto][port]
                    results["openPorts"].append({
                        "port": port,
                        "protocol": proto,
                        "service": service.get("name", "")
                    })
                    results["services"].append({
                        "service": service.get("name", ""),
                        "banner": service.get("product", "") + " " + service.get("version", ""),
                        "port": port,
                    })
        if options.get("weakConfigs"):
            weak_findings = []

            risky_ports = {
                21: ("FTP (insecure)", "FTP service allows unauthenticated access by default.", "medium"),
                23: ("Telnet (insecure)", "Telnet transmits data in plaintext, including credentials.", "high"),
                80: ("HTTP without HTTPS", "Unencrypted HTTP traffic can be intercepted.", "medium"),
                139: ("SMB v1", "SMB v1 is outdated and vulnerable to EternalBlue.", "high"),
                445: ("SMB", "SMB service is exposed and could leak sensitive data.", "medium"),
                3306: ("MySQL default port", "MySQL is exposed on default port without validation.", "medium"),
                3389: ("RDP open", "Remote Desktop Protocol is exposed to the internet.", "high"),
                6379: ("Redis default port", "Redis by default does not require auth.", "high"),
                5432: ("PostgreSQL default port", "Database service exposed on default port.", "medium"),
                27017: ("MongoDB default port", "MongoDB may allow unauth access if not configured.", "high"),
                22: ("Open SSH", "SSH is accessible and should be checked for hardening.", "low")
            }

            for port_info in results["openPorts"]:
                port = port_info["port"]
                if port in risky_ports:
                    title, desc, severity = risky_ports[port]
                    weak_findings.append({
                        "title": title,
                        "description": desc,
                        "severity": severity
                    })

            for svc in results["services"]:
                name = svc["service"].lower()
                banner = svc["banner"].lower()

                if "outdated" in banner or "deprecated" in banner:
                    weak_findings.append({
                        "title": "Outdated service detected",
                        "description": f"Service banner indicates outdated software: {banner}",
                        "severity": "medium"
                    })

                if name == "http" and all(other["service"] != "https" for other in results["services"]):
                    weak_findings.append({
                        "title": "No HTTPS detected",
                        "description": "HTTP is enabled, but HTTPS is not found.",
                        "severity": "medium"
                    })

                if name == "ftp" and "anonymous" in banner:
                    weak_findings.append({
                        "title": "Anonymous FTP access",
                        "description": "FTP server allows anonymous login, which is insecure.",
                        "severity": "high"
                    })

                if name == "redis" and ("unauth" in banner or "no password" in banner):
                    weak_findings.append({
                        "title": "Unauthenticated Redis",
                        "description": "Redis server allows connections without authentication.",
                        "severity": "high"
                    })

                if name == "ssh" and ("openssh_4" in banner or "openssh_5" in banner):
                    weak_findings.append({
                        "title": "Weak SSH version",
                        "description": f"Detected vulnerable SSH version: {banner}",
                        "severity": "medium"
                    })

                if name in ["mysql", "postgresql", "mongodb"] and "auth" not in banner:
                    weak_findings.append({
                        "title": f"Unauthenticated {name.capitalize()}",
                        "description": f"{name.capitalize()} may be accessible without authentication.",
                        "severity": "high"
                    })

            results["weakConfigurations"] = weak_findings



        if options.get("fetchCVEs"):

            def fetch_cves_nvd(service, version=""):
                base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                query = f"{service} {version}".strip()
                params = {
                    "keywordSearch": query,
                    "resultsPerPage": 5
                }
                headers = {
                    "User-Agent": "VulnScanner/1.0"
                }
                try:
                    resp = requests.get(base_url, params=params, headers=headers, timeout=10)
                    if resp.ok:
                        data = resp.json()
                        cves = []
                        for item in data.get("vulnerabilities", []):
                            cve_id = item["cve"]["id"]
                            desc = item["cve"]["descriptions"][0]["value"]
                            cvss = item["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                            severity = (
                                "critical" if cvss != "N/A" and float(cvss) >= 9 else
                                "high" if cvss != "N/A" and float(cvss) >= 7 else
                                "medium" if cvss != "N/A" and float(cvss) >= 4 else
                                "low"
                            )
                            cves.append({
                                "id": cve_id,
                                "description": desc,
                                "cvss": cvss,
                                "severity": severity
                            })
                        return cves
                except Exception as e:
                    print(f"NVD error: {e}")
                return []

            seen_cves = set()
            for svc in results["services"]:
                service = svc["service"].lower()
                banner = svc["banner"]
                version = ""
                match = re.search(r"(\d+\.\d+(?:\.\d+)*)", banner)
                if match:
                    version = match.group(1)
                cve_list = fetch_cves_nvd(service, version)  
                for cve in cve_list:
                    if cve["id"] not in seen_cves:
                        results["cves"].append(cve)
                        seen_cves.add(cve["id"])

        return jsonify(results)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)
