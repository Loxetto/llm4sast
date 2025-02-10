import os
import time
import requests
import subprocess

# Configurazioni
SONAR_HOST_URL = "http://localhost:9000"
SONAR_PROJECT_KEY = "llm4sast"
SONAR_LOGIN = "sqp_0e63a60f61e7977b02928be29a51ad2bb41d6734"
REPORTS_DIR = "reports"

# Creazione cartella report
os.makedirs(REPORTS_DIR, exist_ok=True)

def wait_for_sonarqube():
    """Attende che SonarQube sia UP"""
    print("🟡 Attendi che SonarQube sia pronto...")
    while True:
        try:
            response = requests.get(f"{SONAR_HOST_URL}/api/system/status")
            if response.status_code == 200 and '"status":"UP"' in response.text:
                print("✅ SonarQube è UP!")
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(5)

def run_sonar_scanner():
    """Esegue SonarScanner"""
    print("🚀 Esecuzione di SonarScanner...")
    subprocess.run([
        "sonar-scanner",
        f"-Dsonar.projectKey={SONAR_PROJECT_KEY}",
        f"-Dsonar.sources=.",
        f"-Dsonar.host.url={SONAR_HOST_URL}",
        f"-Dsonar.login={SONAR_LOGIN}"
    ])

def download_report():
    """Scarica il report JSON di SonarQube"""
    print("📥 Scarico il report JSON...")
    url = f"{SONAR_HOST_URL}/api/issues/search?componentKeys={SONAR_PROJECT_KEY}&types=VULNERABILITY,BUG,CODE_SMELL&ps=500"
    response = requests.get(url, auth=(SONAR_LOGIN, ""))
    if response.status_code == 200:
        with open(f"{REPORTS_DIR}/sonarqube_report.json", "w", encoding="utf-8") as f:
            f.write(response.text)
        print(f"✅ Report salvato in {REPORTS_DIR}/sonarqube_report.json")
    else:
        print("❌ Errore durante il download del report!")

if __name__ == "__main__":
    wait_for_sonarqube()
    run_sonar_scanner()
    time.sleep(10)  # Attendi 10 secondi per il processamento
    download_report()
