#!/usr/bin/env python3
import os
import json
import argparse
import requests
import time

# -------------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------------
DEBUG = True

LM_STUDIO_URL = "http://127.0.0.1:1234/v1/completions"

ALL_AVAILABLE_MODELS = {
    "deepcode": "deepcode-7b-aurora-v13",
    "deepseek": "deepseek-coder-v2-lite-instruct",
    "starcoder": "dolphincoder-starcoder2-7b",
    "llama8B": "meta-llama-3.1-8b-instruct",
    "llama3B": "llama-3.2-3b-instruct"
}

CODE_DIR = "../src/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode_tmp"

INCREMENTAL_REPORT_PATH = "../reports/incremental_report.json"
FINAL_REPORT_PATH = "../reports/final_report.json"

SONARQUBE_REPORT_PATH = "../reports/sonarqube_report_min.json"
SEMGREP_REPORT_PATH = "../reports/semgrep_report_min.json"

MAX_TOKENS = 4096
RESERVED_TOKENS = 500
N_PREDICT = 1024

TEXT_FILE_EXTENSIONS = {".java", ".js"}

# -------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------------------------------
def debug_print(msg: str):
    """Stampa messaggi di debug se DEBUG è attivo."""
    if DEBUG:
        print(f"[DEBUG] {msg}")

def maybe_load_json_file(path: str) -> dict:
    """Carica un file JSON se esiste, altrimenti restituisce un dizionario vuoto."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

def filter_sonarqube_issues(sonarqube_path: str, target_file: str) -> str:
    """
    Filtra il report di SonarQube per restituire solo le vulnerabilità
    relative al file analizzato.
    """
    sonarqube_data = maybe_load_json_file(sonarqube_path)
    issues = sonarqube_data.get("issues", [])

    target_file_basename = os.path.basename(target_file)
    filtered_issues = [
        issue for issue in issues 
        if target_file_basename in os.path.basename(issue.get("file", ""))
    ]

    return json.dumps({"sonarqube": filtered_issues}, ensure_ascii=False)

def filter_semgrep_issues(semgrep_path: str, target_file: str) -> str:
    """
    Filtra il report di Semgrep per restituire solo le vulnerabilità
    relative al file analizzato.
    """
    semgrep_data = maybe_load_json_file(semgrep_path)
    findings = semgrep_data.get("results", [])

    target_file_basename = os.path.basename(target_file)
    filtered_findings = [
        finding for finding in findings 
        if target_file_basename in os.path.basename(finding.get("path", ""))
    ]

    return json.dumps({"semgrep": filtered_findings}, ensure_ascii=False)

def build_prompt(code_chunk: str, file_path: str, sonarqube_path: str, semgrep_path: str) -> str:
    """
    Costruisce il prompt includendo solo le vulnerabilità del file attuale.
    """
    sonarqube_json_str = filter_sonarqube_issues(sonarqube_path, file_path)
    semgrep_json_str = filter_semgrep_issues(semgrep_path, file_path)

    prompt = f"""
You are a security expert LLM for sensitive data detection in source code.

Before analyzing the code, consider the SAST findings:
{{
  "sonarqube_issues": {sonarqube_json_str},
  "semgrep_issues": {semgrep_json_str}
}}

Analyze the following code snippet:
{code_chunk}
"""

    debug_print(f"\n[INFO] Prompt generato per {file_path}:\n{prompt}\n{'-'*80}")
    return prompt.strip()

def request_llm(model_name: str, prompt: str) -> dict:
    """
    Manda il prompt al modello e restituisce la risposta.
    """
    payload = {
        "model": model_name,
        "prompt": prompt,
        "max_tokens": N_PREDICT,
        "temperature": 0.2
    }

    debug_print(f"Invio prompt al modello={model_name}")

    try:
        response = requests.post(LM_STUDIO_URL, json=payload)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Connessione fallita con {LM_STUDIO_URL}: {e}")
        return {}

    if response.status_code != 200:
        print(f"[ERROR] Errore dal server LLM {response.status_code}: {response.text}")
        return {}

    try:
        return response.json()
    except json.JSONDecodeError:
        print("[ERROR] Il server LLM ha restituito un formato non valido (non JSON).")
        return {}

# -------------------------------------------------------------------------
# FUNZIONE DI SALVATAGGIO INCREMENTALE
# -------------------------------------------------------------------------
def save_incremental_findings(file_path: str, findings: list):
    """
    Legge l'incremental report, vi appende i nuovi findings e lo riscrive.
    """
    # Carica il report corrente (potrebbe essere vuoto se è all'inizio)
    report = maybe_load_json_file(INCREMENTAL_REPORT_PATH)
    if "findings" not in report:
        report["findings"] = []

    entry = {
        "file": file_path,
        "findings": findings if findings else "No findings detected"
    }

    report["findings"].append(entry)

    # Riscrive il report aggiornato
    with open(INCREMENTAL_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    debug_print(f"📄 Aggiunti findings per {file_path} in {INCREMENTAL_REPORT_PATH}")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Scan code with chosen LLM models + SAST data.")
    parser.add_argument("--models", type=str, default="meta-llama-3.1-8b-instruct",
                        help="Comma-separated list of model keys to use.")
    args = parser.parse_args()

    models_chosen = [m.strip() for m in args.models.split(",") if m.strip()]

    total_files_scanned = 0
    affected_files = set()
    vulnerability_counts = {}
    total_vulnerabilities = 0
    start_time = time.time()

    # ---------------------------------------------------------
    # RICREA IL FILE INCREMENTAL REPORT DA ZERO PRIMA DI PARTIRE
    # ---------------------------------------------------------
    initial_structure = {"findings": []}
    with open(INCREMENTAL_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(initial_structure, f, indent=2, ensure_ascii=False)
    debug_print(f"📄 Ricreato da zero: {INCREMENTAL_REPORT_PATH}")

    # ---------------------------------------------------------
    # AVVIO SCANSIONE
    # ---------------------------------------------------------
    for root, _, files in os.walk(CODE_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            if not file_path.endswith(tuple(TEXT_FILE_EXTENSIONS)):
                continue

            total_files_scanned += 1
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                code_content = f.read()

            code_chunks = [code_content]  # Per ora niente suddivisione in chunk

            for chunk in code_chunks:
                prompt = build_prompt(chunk, file_path, SONARQUBE_REPORT_PATH, SEMGREP_REPORT_PATH)

                for model_key in models_chosen:
                    model_name = ALL_AVAILABLE_MODELS[model_key]
                    response = request_llm(model_name, prompt)

                    findings_text = response.get("choices", [{}])[0].get("text", "")

                    if findings_text:
                        # Prova a interpretare la risposta del modello come JSON
                        try:
                            findings_json = json.loads(findings_text)
                            findings = findings_json.get("findings", [])

                            if findings:
                                affected_files.add(file_path)
                                total_vulnerabilities += len(findings)

                                for finding in findings:
                                    vuln_type = finding.get("vulnerability_type", "Unknown")
                                    vulnerability_counts[vuln_type] = vulnerability_counts.get(vuln_type, 0) + 1

                                # Salva i findings (append) nel report incrementale
                                save_incremental_findings(file_path, findings)
                        except json.JSONDecodeError:
                            print("[ERROR] Il modello ha restituito un JSON non valido.")

    # ---------------------------------------------------------
    # PRODUCE IL REPORT FINALE DI SINTESI
    # ---------------------------------------------------------
    execution_time = time.time() - start_time
    final_report = {
        "total_files_scanned": total_files_scanned,
        "total_vulnerabilities": total_vulnerabilities,
        "total_affected_files": len(affected_files),
        "vulnerabilities_by_type": vulnerability_counts,
        "execution_time_seconds": execution_time
    }

    with open(FINAL_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    print(f"[OK] Analisi completata. Report finale salvato in {FINAL_REPORT_PATH}.")

if __name__ == "__main__":
    main()
