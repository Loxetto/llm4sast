#!/usr/bin/env python3
import os
import sys
import json
import re
import argparse
import requests

try:
    import tiktoken
except ImportError:
    tiktoken = None
    print("[WARN] 'tiktoken' not installed. Will use approximate token counting fallback.")

# -------------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------------
DEBUG = True

# LM STUDIO single endpoint
LM_STUDIO_URL = "http://127.0.0.1:1234/v1/completions"  # Adjust as needed

# Dictionary of *all* possible models you might want to use:
ALL_AVAILABLE_MODELS = {
    "deepcode":  "deepcode-7b-aurora-v13",
    "deepseek":  "deepseek-coder-v2-lite-instruct",
    "starcoder": "dolphincoder-starcoder2-7b",
    "llama8B":   "meta-llama-3.1-8b-instruct",
    "llama3B":   "llama-3.2-3b-instruct"
}

CODE_DIR = "./src/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode_tmp"

# Where partial/final files are stored
PARTIAL_PREFIX = "partial_findings_"
FINAL_JSON_PATH = "final_report.json"

# SAST file paths
SEM_GREP_REPORT_PATH = "./reports/semgrep_report.json"
SONARQUBE_REPORT_PATH = "./reports/sonarqube_report.json"

# Token constraints
MAX_TOKENS = 4096
RESERVED_TOKENS = 500
N_PREDICT = 1024

# We only scan these file extensions
TEXT_FILE_EXTENSIONS = {".java", ".js"}

# -------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------------------------------
def debug_print(msg: str):
    if DEBUG:
        print(f"[DEBUG] {msg}")

def approximate_token_count(text: str) -> int:
    return len(text) // 4

def count_tokens(text: str, model_name: str = "GenericModel") -> int:
    if tiktoken is None:
        return approximate_token_count(text)
    try:
        encoding = tiktoken.encoding_for_model(model_name)
        return len(encoding.encode(text))
    except Exception:
        return approximate_token_count(text)

def load_partial_findings(file_path: str) -> list:
    if not os.path.isfile(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("findings", [])
    except (json.JSONDecodeError, OSError):
        return []

def save_partial_findings(file_path: str, findings_list: list):
    data = {"findings": findings_list}
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def request_llm(model_name: str, prompt: str) -> dict:
    payload = {
        "model": model_name,
        "prompt": prompt,
        "max_tokens": N_PREDICT,
        "temperature": 0.2
    }

    n_tokens = count_tokens(prompt, model_name)
    debug_print(f"Sending prompt (~{n_tokens} tokens) to model={model_name}")

    try:
        response = requests.post(LM_STUDIO_URL, json=payload)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to {LM_STUDIO_URL}: {e}")
        return {}

    if response.status_code != 200:
        print(f"[ERROR] LLM server error {response.status_code}: {response.text}")
        return {}

    try:
        return response.json()
    except json.JSONDecodeError:
        print("[ERROR] LLM server returned non-JSON.")
        return {}

def maybe_load_json_file(path: str) -> dict:
    """Loads a JSON file or returns {} if not found/invalid."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

def build_sast_json_str(semgrep_path: str, sonarqube_path: str) -> str:
    """
    Loads semgrep & sonarqube JSON, merges into a single { "semgrep":..., "sonarqube":... },
    and returns it as a string.
    If it's too large, we do a naive truncation.
    """
    semgrep_data = maybe_load_json_file(semgrep_path)
    sonarqube_data = maybe_load_json_file(sonarqube_path)
    combined = {
        "semgrep": semgrep_data,
        "sonarqube": sonarqube_data
    }
    raw_str = json.dumps(combined, ensure_ascii=False)

    # If too big, we can truncate:
    # We'll do a simple approach: if > 5000 chars, slice it.
    if len(raw_str) > 5000:
        raw_str = raw_str[:5000] + "...(truncated)..."

    return raw_str


def build_prompt(code_chunk: str, file_path: str, sast_json_str: str) -> str:
    """
    Prompt instructing the model to produce a fully populated JSON
    according to your Security Findings schema, plus including SAST data.
    """
    schema_snippet = r"""
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/llm-security-findings.schema.json",
  "title": "LLM-based Security Findings Report",
  "type": "object",
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "file_path": { "type": "string" },
          "line": { "type": ["integer","string"] },
          "description": { "type": "string" },
          "cwe_ids": {
            "type": "array",
            "items": { "type": "string" }
          },
          "severity": {
            "type": "string",
            "enum": ["info","low","medium","high","critical"]
          },
          "confidence": {
            "type": "string",
            "enum": ["low","medium","high"]
          },
          "references": {
            "type": "array",
            "items": {"type":"string","format":"uri"}
          },
          "model": { "type": "string" },
          "recommendation": { "type": "string" }
        },
        "required": ["file_path","line","description","severity"]
      }
    }
  },
  "required": ["findings"]
}
"""

    prompt = f"""
You are a security expert LLM for sensitive data detection in source code.

Use the following JSON schema to produce your output. Do not leave empty fields like 'description'.
If no vulnerabilities, just output {{ "findings": [] }}.

Here is the JSON schema (shortened):
{schema_snippet}

We also have some SAST tool reports (semgrep & sonarqube), can help you using the to detect vulenarabilities and lower the false positive, SO BE CAREFUL:
SAST REPORTS:
{sast_json_str}

RULES:
1) Output only valid JSON (top-level "findings" array).
2) For each vulnerability, fill 'description' with a meaningful explanation.
3) Provide 'cwe_ids' if relevant.
4) Provide 'recommendation' if possible.
5) Provide 'confidence' as "low","medium", or "high".

CODE (file: {file_path}):
{code_chunk}
"""
    return prompt.strip()

def parse_llm_findings(llm_response: dict, fallback_path: str, model_id: str) -> list:
    findings = []
    choices = llm_response.get("choices", [])
    if not choices:
        return findings

    raw_text = choices[0].get("text", "").strip()
    if not raw_text:
        return findings

    try:
        obj = json.loads(raw_text)
        chunk_findings = obj.get("findings", [])
    except json.JSONDecodeError:
        chunk_findings = []

    for item in chunk_findings:
        fp = item.get("file_path", fallback_path)
        ln = item.get("line", 0)
        desc = item.get("description", "No description provided")
        sev  = item.get("severity", "info")
        cwe  = item.get("cwe_ids", [])
        conf = item.get("confidence", "medium")
        rec  = item.get("recommendation", "No recommendation")
        refs = item.get("references", [])
        m    = item.get("model", model_id)

        findings.append({
            "file_path": fp,
            "line": ln,
            "description": desc,
            "severity": sev,
            "cwe_ids": cwe,
            "confidence": conf,
            "recommendation": rec,
            "references": refs,
            "model": m
        })

    return findings

def is_text_file(file_path: str) -> bool:
    _, ext = os.path.splitext(file_path)
    return ext.lower() in TEXT_FILE_EXTENSIONS

def unify_and_finalize(models_chosen: list, total_files_scanned: int):
    all_findings = []
    for m in models_chosen:
        partial_file = PARTIAL_PREFIX + m + ".json"
        model_findings = load_partial_findings(partial_file)
        all_findings.extend(model_findings)

    total_vulns = len(all_findings)
    cwe_map = {}
    for fitem in all_findings:
        for c in fitem.get("cwe_ids", []):
            cwe_map[c] = cwe_map.get(c, 0) + 1

    files_affected = {f["file_path"] for f in all_findings}
    pct_affected = 0.0
    if total_files_scanned > 0:
        pct_affected = (len(files_affected) / total_files_scanned) * 100

    final_data = {
        "summary": {
            "status": "Scan complete",
            "files_scanned": total_files_scanned,
            "total_vulnerabilities": total_vulns,
            "percentage_files_affected": round(pct_affected, 2)
        },
        "cwe_counts": cwe_map,
        "vulnerabilities": all_findings
    }

    with open(FINAL_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=2, ensure_ascii=False)

    print(f"[OK] Final consolidated report => {FINAL_JSON_PATH}")
    print(f"Models used => {models_chosen}")
    for m in models_chosen:
        print(f"Partial for {m} => {PARTIAL_PREFIX + m + '.json'}")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Scan code with chosen LLM models + SAST data.")
    parser.add_argument("--models", type=str, default="meta-llama-3.1-8b-instruct",
                        help="Comma-separated list of model keys to use (e.g. deepcode,deepseek,starcoder,llama8B,llama3B).")
    args = parser.parse_args()

    # Parse user choice
    models_chosen = [m.strip() for m in args.models.split(",") if m.strip()]
    # Validate model keys
    for m in models_chosen:
        if m not in ALL_AVAILABLE_MODELS:
            print(f"[ERROR] Unknown model key: {m}. Allowed: {list(ALL_AVAILABLE_MODELS.keys())}")
            sys.exit(1)

    # Prepare partial files
    for m in models_chosen:
        file_path = PARTIAL_PREFIX + m + ".json"
        save_partial_findings(file_path, [])  # empty at start

    if not os.path.isdir(CODE_DIR):
        print(f"[ERROR] Code directory '{CODE_DIR}' not found.")
        sys.exit(1)

    # Build SAST JSON (semgrep + sonarqube) once
    sast_reports_str = build_sast_json_str(SEM_GREP_REPORT_PATH, SONARQUBE_REPORT_PATH)

    available_code_tokens = MAX_TOKENS - RESERVED_TOKENS
    debug_print(f"Available tokens for code chunk: {available_code_tokens}")

    total_files_scanned = 0

    for root, _, files in os.walk(CODE_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            if not is_text_file(file_path):
                debug_print(f"Skipping non-text file: {file_path}")
                continue

            total_files_scanned += 1
            debug_print(f"Reading file: {file_path}")
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    code_content = f.read()
            except OSError as e:
                print(f"[ERROR] Cannot read '{file_path}': {e}")
                continue

            lines = code_content.split("\n")
            code_chunks = []
            current_lines = []
            current_token_count = 0

            for line in lines:
                line_token_count = count_tokens(line + "\n")
                if current_token_count + line_token_count > available_code_tokens:
                    code_chunks.append("\n".join(current_lines))
                    current_lines = [line]
                    current_token_count = line_token_count
                else:
                    current_lines.append(line)
                    current_token_count += line_token_count

            if current_lines:
                code_chunks.append("\n".join(current_lines))

            debug_print(f"File '{file_path}' => {len(code_chunks)} chunk(s)")

            for chunk_idx, chunk in enumerate(code_chunks, start=1):
                # Build prompt with SAST data
                prompt = build_prompt(chunk, file_path, sast_reports_str)

                # For each chosen model
                for model_key in models_chosen:
                    model_name = ALL_AVAILABLE_MODELS[model_key]
                    resp = request_llm(model_name, prompt)
                    new_findings = parse_llm_findings(resp, file_path, model_name)

                    if new_findings:
                        partial_path = PARTIAL_PREFIX + model_key + ".json"
                        existing = load_partial_findings(partial_path)
                        existing.extend(new_findings)
                        save_partial_findings(partial_path, existing)
                        debug_print(f"[INFO] Model={model_key} found {len(new_findings)} issues in chunk {chunk_idx} => partial updated.")

    unify_and_finalize(models_chosen, total_files_scanned)
    sys.exit(0)


if __name__ == "__main__":
    main()
