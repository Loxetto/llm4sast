import requests
import base64

SONAR_HOST_URL = "http://localhost:9000"
SONAR_PROJECT_KEY = "llm4sast"
SONAR_LOGIN = "sqp_xxx"
REPORTS_DIR = "./reports"
OUTPUT_FILE = f"{REPORTS_DIR}/sonarqube_report.json"

# Crea cartella report se non esiste
import os
os.makedirs(REPORTS_DIR, exist_ok=True)

# Autenticazione Base64
auth_header = {
    "Authorization": "Basic " + base64.b64encode(f"{SONAR_LOGIN}:".encode()).decode()
}

# API Request
url = f"{SONAR_HOST_URL}/api/issues/search?componentKeys={SONAR_PROJECT_KEY}&types=VULNERABILITY,BUG,CODE_SMELL&ps=500"
response = requests.get(url, headers=auth_header)

# Salva il report JSON
if response.status_code == 200:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(response.text)
    print(f"✅ Report salvato in {OUTPUT_FILE}")
else:
    print(f"❌ Errore {response.status_code}: {response.text}")