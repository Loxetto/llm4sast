import json
import os

# Percorsi file
INCREMENTAL_REPORT_PATH = "incremental_report.json"
OWASP_BENCHMARK_PATH = "owasp_benchmark_results.json"  # Contiene i risultati attesi da OWASP
FALSE_POSITIVES_REPORT = "false_positives_report.json"

def load_json(file_path):
    """Carica un file JSON."""
    if not os.path.isfile(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def compare_results():
    """
    Confronta i risultati del modello con il benchmark OWASP per identificare i falsi positivi.
    """
    # Carica i risultati della scansione e del benchmark
    incremental_results = load_json(INCREMENTAL_REPORT_PATH)
    benchmark_results = load_json(OWASP_BENCHMARK_PATH)

    if "findings" not in incremental_results:
        print("[ERROR] Nessun dato trovato nel report incrementale.")
        return

    false_positives = []
    
    for result in incremental_results["findings"]:
        file_path = result["file"]
        findings = result["findings"]

        # Cerca se il file è presente nel benchmark
        benchmark_entry = next((item for item in benchmark_results if item["file"] == file_path), None)

        if not benchmark_entry:
            print(f"[WARN] Nessun dato benchmark trovato per {file_path}, impossibile valutare falsi positivi.")
            continue

        for finding in findings:
            line = finding.get("line")
            description = finding.get("description")

            # Verifica se la vulnerabilità è segnalata da OWASP
            benchmark_vulnerabilities = benchmark_entry.get("true_positives", [])
            if not any(vuln["line"] == line and vuln["description"] in description for vuln in benchmark_vulnerabilities):
                # Se la vulnerabilità trovata non è segnalata da OWASP, è un falso positivo
                false_positives.append({
                    "file": file_path,
                    "line": line,
                    "description": description
                })

    # Salva il report dei falsi positivi
    with open(FALSE_POSITIVES_REPORT, "w", encoding="utf-8") as f:
        json.dump({"false_positives": false_positives}, f, indent=2)

    print(f"[INFO] Report dei falsi positivi generato: {FALSE_POSITIVES_REPORT}")

if __name__ == "__main__":
    compare_results()
