🔐 Mini-Nessus - Vulnerability Scanner

Mini-Nessus is a lightweight vulnerability scanner built using Flask and Nmap. It performs port scanning, fetches CVEs using the NVD API, and detects weak security configurations across open services. It's a great project for cybersecurity students, ethical hackers, and security enthusiasts looking to understand how scanners like Nessus work under the hood.

🚀 Features

🔎 Port and Service Detection using Nmap

📦 CVE Retrieval from the NVD (National Vulnerability Database)

⚠️ Weak Configuration Detection

📊 Clean JSON API Output for Integration with Frontends

🧠 Beginner-friendly Python codebase

⚙️ Tech Stack

Backend: Python, Flask

Port Scanning: python-nmap (Nmap wrapper)

CVE API: NVD REST API (No Auth Key Required)

Frontend: HTML/CSS + JS (optional integration)

🧪 How It Works

Sends a POST request with a target IP and options (like fetchCVEs and weakConfigs).

Uses nmap to detect open ports and services with version info.

Parses service banners to:

Detect outdated/weak configurations

Extract service + version for CVE query

Fetches relevant CVEs via the NVD API.

Returns all results in JSON format.

📦 Installation

Prerequisites:

Python 3.7+

Nmap installed on your machine
# Clone the repository
git clone https://github.com/yourusername/mini-nessus.git
cd mini-nessus

# Install Python dependencies
pip install -r requirements.txt

# Run the Flask App
python app.py

🛡️ Disclaimer

This tool is intended for educational and authorized testing only. Do not scan systems without explicit permission. The author is not responsible for misuse.

👨‍💻 Author

Abhishek Iyer GitHub: @abhi-lak 
