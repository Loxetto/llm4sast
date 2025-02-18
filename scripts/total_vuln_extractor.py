import os
import json
from bs4 import BeautifulSoup

# Directory dei file HTML caricati
html_files = {
    "Command Injection": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/cmdi-Index.html",
    "Weak Encryption": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/crypto-Index.html",
    "Weak Hashing": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/hash-Index.html",
    "LDAP Injection": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/ldapi-Index.html",
    "Path Traversal": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/pathtraver-Index.html",
    "Insecure Cookie": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/securecookie-Index.html",
    "SQL Injection": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/sqli-Index.html",
    "Trust Boundary": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/trustbound-Index.html",
    "Weak Randomness": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/weakrand-Index.html",
    "XPath Injection": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/xpathi-Index.html",
    "Cross Site Scripting": "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/src/main/webapp/xss-Index.html",
}

# Lista per raccogliere i risultati
vulnerable_files = []

# Funzione per estrarre i test case dai file HTML
def extract_vulnerable_tests(file_path, vulnerability_type):
    with open(file_path, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")
    
    # Trova tutti i link ai test case
    for link in soup.find_all("a"):
        test_name = link.text.strip()
        if "BenchmarkTest" in test_name:  # Assicuriamoci che sia un test valido
            vulnerable_files.append({
                "file": f"{test_name}.java",
                "vulnerability_type": vulnerability_type,
                "is_vulnerable": True
            })

# Iteriamo su tutti i file HTML e estraiamo i test
for vuln_type, file_path in html_files.items():
    if os.path.exists(file_path):
        extract_vulnerable_tests(file_path, vuln_type)
    else:
        print(f"[WARNING] File non trovato: {file_path}")

# Scrittura in un unico file JSON
output_json_path = "benchmark_vulnerable_tests.json"
with open(output_json_path, "w", encoding="utf-8") as f:
    json.dump(vulnerable_files, f, indent=4)

# Mostrare il percorso del file JSON generato
output_json_path
