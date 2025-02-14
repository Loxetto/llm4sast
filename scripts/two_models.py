#!/usr/bin/env python3
import os
import sys
import json
import re
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

# LM Studio single endpoint
LM_STUDIO_URL = "http://127.0.0.1:1234/v1/completions"  # Adjust to your actual route.

# Two model names loaded in LM Studio:
MODEL_DC = "deepcode-7b-aurora-v13"
MODEL_DS = "deepseek-coder-v2-lite-instruct"

CODE_DIR = "../src/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode_low"

# Partial & final JSON file paths
PARTIAL_DC_JSON = "partial_findings_deepcode.json"
PARTIAL_DS_JSON = "partial_findings_deepseek.json"
FINAL_JSON = "final_report.json"

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

def load_partial_findings(path: str) -> list:
    """Loads existing partial JSON or returns empty list if none."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("findings", [])
    except (json.JSONDecodeError, OSError):
        return []

def save_partial_findings(path: str, findings_list: list):
    """Writes { "findings": [...] } to the given file path."""
    data = {"findings": findings_list}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def request_llm(model_name: str, prompt: str) -> dict:
    """
    POSTs to LM Studio, specifying the 'model' in the JSON body.
    We handle any errors and return the top-level JSON if possible.
    """
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

def build_prompt(code_chunk: str, file_path: str) -> str:
    """
    Double braces for literal { } in f-string. 
    If no vulnerabilities, produce { "findings":[] }.
    """
    prompt = f"""
You are a security expert LLM for sensitive data detection in source code.

RULES:
- If uncertain or no vulnerabilities, do NOT produce an empty response. Produce {{\"findings\":[]}}.
- You MUST output valid JSON with a top-level "findings" array.
  Example: {{
    "findings": [
      {{
        "file_path": "some/path",
        "line": 123,
        "message": "description",
        "severity": "error|warning|info"
      }}
    ]
  }}
- No explanations, only that JSON.

CODE (file: {file_path}):
{code_chunk}
"""
    return prompt.strip()

def parse_llm_findings(llm_response: dict, fallback_path: str) -> list:
    """
    Extract "findings" from the LLM's JSON. If empty or invalid, return [].
    """
    findings = []
    choices = llm_response.get("choices", [])
    if not choices:
        return findings

    raw_text = choices[0].get("text", "").strip()
    if not raw_text:
        return findings

    try:
        data = json.loads(raw_text)
        chunk_findings = data.get("findings", [])
    except json.JSONDecodeError:
        chunk_findings = []

    for item in chunk_findings:
        fp = item.get("file_path", fallback_path)
        ln = item.get("line", 0)
        msg = item.get("message", "")
        sev = item.get("severity", "info")
        findings.append({
            "file_path": fp,
            "line": ln,
            "message": msg,
            "severity": sev
        })

    return findings

def extract_cwe_from_message(message: str) -> list:
    pattern = r"(CWE-\d+)"
    return re.findall(pattern, message)

def is_text_file(file_path: str) -> bool:
    _, ext = os.path.splitext(file_path)
    return ext.lower() in TEXT_FILE_EXTENSIONS

def finalize_reports(total_files_scanned: int):
    """
    Merge partial results from both models, tag them with 'model',
    produce a final combined JSON.
    """
    # Load partial findings from each model
    dc_findings = load_partial_findings(PARTIAL_DC_JSON)
    ds_findings = load_partial_findings(PARTIAL_DS_JSON)

    # Tag each
    for f in dc_findings:
        f["model"] = MODEL_DC
    for f in ds_findings:
        f["model"] = MODEL_DS

    all_findings = dc_findings + ds_findings
    total_vulns = len(all_findings)

    cwe_map = {}
    for finding in all_findings:
        cwes = extract_cwe_from_message(finding["message"])
        for cwe in cwes:
            cwe_map[cwe] = cwe_map.get(cwe, 0) + 1

    affected_files = {x["file_path"] for x in all_findings}
    pct_files_affected = 0.0
    if total_files_scanned > 0:
        pct_files_affected = (len(affected_files) / total_files_scanned) * 100

    final_data = {
        "summary": {
            "status": "Scan complete for two models",
            "files_scanned": total_files_scanned,
            "total_vulnerabilities": total_vulns,
            "percentage_files_affected": round(pct_files_affected, 2)
        },
        "cwe_counts": cwe_map,
        "vulnerabilities": all_findings
    }

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=2, ensure_ascii=False)

    print(f"[OK] Final consolidated report => {FINAL_JSON}")
    print(f"DeepCode partial => {PARTIAL_DC_JSON}")
    print(f"DeepSeek partial => {PARTIAL_DS_JSON}")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    # Check CODE_DIR
    if not os.path.isdir(CODE_DIR):
        print(f"[INFO] Directory '{CODE_DIR}' not found. Exiting.")
        sys.exit(0)

    # Initialize partial files empty
    save_partial_findings(PARTIAL_DC_JSON, [])
    save_partial_findings(PARTIAL_DS_JSON, [])

    available_code_tokens = MAX_TOKENS - RESERVED_TOKENS
    debug_print(f"Available tokens for code chunk: {available_code_tokens}")

    total_files_scanned = 0

    # Walk the code directory
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

            # For each chunk, query both models
            for chunk_idx, chunk in enumerate(code_chunks, start=1):
                prompt = build_prompt(chunk, file_path)

                # 1) DeepCode
                resp_dc = request_llm(MODEL_DC, prompt)
                dc_chunk_findings = parse_llm_findings(resp_dc, file_path)
                if dc_chunk_findings:
                    # Load partial
                    partial_dc = load_partial_findings(PARTIAL_DC_JSON)
                    # Extend
                    partial_dc.extend(dc_chunk_findings)
                    # Save partial
                    save_partial_findings(PARTIAL_DC_JSON, partial_dc)
                    debug_print(f"[INFO] DeepCode found {len(dc_chunk_findings)} new vulns for chunk {chunk_idx} => partial updated.")

                # 2) DeepSeek
                resp_ds = request_llm(MODEL_DS, prompt)
                ds_chunk_findings = parse_llm_findings(resp_ds, file_path)
                if ds_chunk_findings:
                    partial_ds = load_partial_findings(PARTIAL_DS_JSON)
                    partial_ds.extend(ds_chunk_findings)
                    save_partial_findings(PARTIAL_DS_JSON, partial_ds)
                    debug_print(f"[INFO] DeepSeek found {len(ds_chunk_findings)} new vulns for chunk {chunk_idx} => partial updated.")

    # After scanning all, produce final
    finalize_reports(total_files_scanned)
    sys.exit(0)

if __name__ == "__main__":
    main()