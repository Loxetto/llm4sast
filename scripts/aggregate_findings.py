import json
import os

INPUT_PATH = "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/scripts/incremental_report.json"
OUTPUT_PATH = "aggregated_findings.json"

def load_json(path):
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def normalize_file_name(file_path: str) -> str:
    """
    Estrae dal path completo il nome base (es. BenchmarkTest00001.java) 
    e rimuove l'estensione .java
    Esempio:
      "./src/BenchmarkJava/.../BenchmarkTest00001.java" -> "BenchmarkTest00001"
    """
    normalized = file_path.replace("\\", "/")
    filename = os.path.basename(normalized)  # es. "BenchmarkTest00001.java"
    if filename.endswith(".java"):
        filename = filename[:-5]  # rimuove ".java"
    return filename

def main():
    data = load_json(INPUT_PATH)
    if "findings" not in data:
        print(f"[ERRORE] Il JSON non contiene la chiave 'findings'.")
        return

    # Dizionario temporaneo dove unire i risultati:
    # Esempio: { "BenchmarkTest00001": set(["Path Traversal", "Command Injection"]), ... }
    aggregated_dict = {}

    for file_item in data["findings"]:
        raw_path = file_item["file"]  # percorso con backslash
        short_name = normalize_file_name(raw_path)

        # Se non abbiamo ancora un record per quel file, lo creiamo
        if short_name not in aggregated_dict:
            aggregated_dict[short_name] = set()

        # Aggiungiamo le vulnerability_types
        for finding in file_item.get("findings", []):
            vuln_type = finding.get("vulnerability_type", "Unknown")
            aggregated_dict[short_name].add(vuln_type)

    # Ora convertiamo in una lista "files" secondo il formato desiderato
    aggregated = {"files": []}
    for short_name, vuln_types in aggregated_dict.items():
        aggregated["files"].append({
            "file": short_name,
            "vulnerability_types": sorted(list(vuln_types))
        })

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=2, ensure_ascii=False)

    print(f"[OK] Creato file aggregato:", OUTPUT_PATH)

if __name__ == "__main__":
    main()
