#!/usr/bin/env python3
import os
import sys
import json
import requests
import tiktoken

# -----------------------------------------------------------------------------
# CONFIGURAZIONE
# -----------------------------------------------------------------------------
LLM_SERVER_URL = "http://127.0.0.1:1234/v1/completions"  # Modello locale
CODE_DIR = "./src"
MAX_TOKENS = 4096  # Limite massimo del modello
RESERVED_TOKENS = 500  # Spazio riservato per il prompt e la struttura JSON
N_PREDICT = 1024  # Numero massimo di token generati

SEM_GREP_REPORT_PATH = "reports/semgrep_report.json"
SONARQUBE_REPORT_PATH = "reports/sonarqube_report.json"

# -----------------------------------------------------------------------------
# FUNZIONI DI SUPPORTO
# -----------------------------------------------------------------------------
def load_json_file(path: str) -> dict:
    """Carica un file JSON e restituisce un dizionario."""
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"[WARN] Errore nel caricamento di {path}. Usando un dizionario vuoto.")
            return {}
    return {}

def count_tokens(text: str, model_name: str = "gpt-3.5-turbo") -> int:
    """Conta il numero di token in un testo usando tiktoken."""
    try:
        encoding = tiktoken.encoding_for_model(model_name)
        return len(encoding.encode(text))
    except Exception:
        print("[WARN] Impossibile determinare il numero di token, uso una stima approssimativa (1 token ~ 4 caratteri).")
        return len(text) // 4  

def split_code_by_tokens(code: str, available_tokens: int, model_name: str = "gpt-3.5-turbo") -> list:
    """
    Divide il codice in chunk che non superano il numero di token disponibili.
    """
    chunks = []
    current_text = []
    current_token_count = 0

    lines = code.split("\n")
    for line in lines:
        line_token_count = count_tokens(line + "\n", model_name=model_name)
        
        # Se l'aggiunta supera il limite, salva il chunk attuale e inizia uno nuovo
        if current_token_count + line_token_count > available_tokens:
            chunks.append("\n".join(current_text))
            current_text = [line]
            current_token_count = line_token_count
        else:
            current_text.append(line)
            current_token_count += line_token_count

    if current_text:
        chunks.append("\n".join(current_text))

    return chunks

def request_llm(prompt: str) -> dict:
    """Invia la richiesta al modello LLM e restituisce la risposta JSON."""
    payload = {
        "prompt": prompt,
        "max_tokens": N_PREDICT,
        "temperature": 0.2
    }

    response = requests.post(LLM_SERVER_URL, json=payload)

    if response.status_code != 200:
        print(f"[ERROR] LLM server ha risposto con errore {response.status_code}. Dettagli: {response.text}")
        sys.exit(1)

    try:
        return response.json()
    except json.JSONDecodeError:
        print("[ERROR] Il server LLM ha restituito una risposta non valida.")
        sys.exit(1)

def build_prompt(code_chunk: str, file_path: str, sast_reports: str) -> str:
    """
    Costruisce il prompt per il modello, mantenendo i report SAST interi
    e spezzando solo il codice sorgente in chunk gestibili.
    """
    prompt = f"""
You are a security expert LLM for sensitive data detection in source code.
You will receive a code chunk along with the corresponding SAST reports.

RULES:
1) Output ONLY valid JSON with a top-level "findings" array.
2) Each object in the "findings" array must have the following keys:
   - "file_path" (string): The path of the file containing the issue.
   - "line" (integer): The line number where the issue was found.
   - "message" (string): A description of the issue found.
   - "severity" (string): The severity of the issue (error/warning/info).
3) The response **MUST NOT** contain anything else than a valid JSON.
4) If no vulnerabilities are found, return:
   {{ "findings": [] }}
5) Do not generate any explanations, only the JSON result.
6) Your input includes a chunk of code and SAST reports.

SAST REPORTS:
{sast_reports}

CODE CHUNK (file: {file_path}):
{code_chunk}
"""
    return prompt.strip()

def main():
    semgrep_report = load_json_file(SEM_GREP_REPORT_PATH)
    sonarqube_report = load_json_file(SONARQUBE_REPORT_PATH)

    sast_reports = json.dumps({"semgrep": semgrep_report, "sonarqube": sonarqube_report}, ensure_ascii=False)

    # Calcola quanti token occupano i report SAST
    sast_tokens = count_tokens(sast_reports)
    
    # Determina quanti token sono disponibili per il codice
    available_code_tokens = MAX_TOKENS - sast_tokens - RESERVED_TOKENS

    if available_code_tokens <= 0:
        print("[ERROR] I report SAST occupano troppo spazio, ridurre il loro contenuto.")
        sys.exit(1)

    if not os.path.isdir(CODE_DIR):
        print(f"[INFO] Directory '{CODE_DIR}' non trovata. Nessun file da analizzare.")
        sys.exit(0)

    any_findings = False

    for root, _, files in os.walk(CODE_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    code_content = f.read()
            except OSError as e:
                print(f"[ERROR] Impossibile leggere '{file_path}': {e}")
                continue

            # Spezza il codice in chunk che rispettano il limite di token
            code_chunks = split_code_by_tokens(code_content, available_code_tokens)

            for chunk_idx, chunk in enumerate(code_chunks, start=1):
                prompt = build_prompt(chunk, file_path, sast_reports)
                
                try:
                    response = request_llm(prompt)
                    findings = response.get("findings", [])
                except RuntimeError as e:
                    print(f"[ERROR] {e}")
                    sys.exit(1)

                if findings:
                    print(f"[BLOCK] Problemi trovati in '{file_path}', chunk {chunk_idx}:")
                    print(json.dumps(findings, indent=2, ensure_ascii=False))
                    any_findings = True

    if any_findings:
        print("[BLOCK] Vulnerabilità rilevate. Commit bloccato.")
        sys.exit(1)
    else:
        print("[OK] Nessun problema trovato. Commit permesso.")
        sys.exit(0)

if __name__ == "__main__":
    main()
