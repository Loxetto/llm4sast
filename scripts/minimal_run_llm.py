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
DEBUG = True  # Toggle debug prints on/off

# LM STUDIO single endpoint for /v1/completions
LM_STUDIO_SERVER_URL = "http://127.0.0.1:1234/v1/completions"  # Adjust to your actual route/port

# Names of the four models loaded in LM Studio:
DEEPCODE_MODEL_NAME = "deepcode-7b-aurora-v13"
DEEPSEEK_MODEL_NAME = "deepseek-coder-v2-lite-instruct"
STARCODER_MODEL_NAME = "dolphincoder-starcoder2-7b"
LLAMA_MODEL_NAME = "llama-3.2-3b-instruct"

CODE_DIR = "../src/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode_low"  # Directory to scan

# Partial & final files
PARTIAL_DC = "partial_findings_deepcode.json"   # partial results from DeepCode
PARTIAL_DS = "partial_findings_deepseek.json"   # partial results from DeepSeek
PARTIAL_SC = "partial_findings_starcoder.json"  # partial results from StarCoder
PARTIAL_LL = "partial_findings_llama.json"      # partial results from LLaMA

FINAL_JSON_PATH = "final_report.json"           # final consolidated report

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
    POST to LM Studio's single /v1/completions, specifying 'model' in the JSON body.
    This resolves 'Multiple models are loaded...' error in LM Studio.
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
        response = requests.post(LM_STUDIO_SERVER_URL, json=payload)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to LM Studio: {e}")
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
    Prompt that instructs the LLM to produce JSON with a "findings" array.
    Double braces for literal { } in f-strings.
    """
    prompt = f"""
You are a security expert LLM for sensitive data detection in source code.

RULES:
- If uncertain or no vulnerabilities, do NOT produce an empty response. Produce {{\"findings\":[]}}.
- You MUST output valid JSON with a top-level "findings" array.
- No explanations or text beyond that JSON.

CODE (file: {file_path}):
{code_chunk}
"""
    return prompt.strip()

def parse_llm_findings(llm_response: dict, fallback_path: str) -> list:
    """
    Extract the "findings" array from an OpenAI-style response.
    If the model gave no text or invalid JSON, interpret as no findings.
    """
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
    """Naive approach to find 'CWE-xxx' references in a message."""
    pattern = r"(CWE-\d+)"
    return re.findall(pattern, message)

def is_text_file(file_path: str) -> bool:
    _, ext = os.path.splitext(file_path)
    return ext.lower() in TEXT_FILE_EXTENSIONS

def finalize_reports(total_files_scanned: int):
    """
    Merge partial findings from all four models, tag each item with "model",
    then produce final_report.json with summary, cwe_counts, etc.
    """
    # Load partial findings
    dc_final = load_partial_findings(PARTIAL_DC)
    ds_final = load_partial_findings(PARTIAL_DS)
    sc_final = load_partial_findings(PARTIAL_SC)
    ll_final = load_partial_findings(PARTIAL_LL)

    # Tag each
    for f in dc_final:
        f["model"] = DEEPCODE_MODEL_NAME
    for f in ds_final:
        f["model"] = DEEPSEEK_MODEL_NAME
    for f in sc_final:
        f["model"] = STARCODER_MODEL_NAME
    for f in ll_final:
        f["model"] = LLAMA_MODEL_NAME

    # Combine all
    all_findings = dc_final + ds_final + sc_final + ll_final
    total_vulns = len(all_findings)

    # Basic cwe map
    cwe_map = {}
    for fitem in all_findings:
        cwes = extract_cwe_from_message(fitem["message"])
        for c in cwes:
            cwe_map[c] = cwe_map.get(c, 0) + 1

    # Percentage of files with >=1 vulnerability
    files_affected = {f["file_path"] for f in all_findings}
    pct_affected = 0.0
    if total_files_scanned > 0:
        pct_affected = (len(files_affected) / total_files_scanned) * 100

    final_data = {
        "summary": {
            "status": "Scan complete (DeepCode, DeepSeek, StarCoder, LLaMA)",
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
    print(f"DeepCode partial => {PARTIAL_DC}")
    print(f"DeepSeek partial => {PARTIAL_DS}")
    print(f"StarCoder partial => {PARTIAL_SC}")
    print(f"LLaMA partial => {PARTIAL_LL}")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    if not os.path.isdir(CODE_DIR):
        print(f"[INFO] Code directory '{CODE_DIR}' not found. Exiting.")
        sys.exit(0)

    # Initialize partial JSONs empty
    save_partial_findings(PARTIAL_DC, [])
    save_partial_findings(PARTIAL_DS, [])
    save_partial_findings(PARTIAL_SC, [])
    save_partial_findings(PARTIAL_LL, [])

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
                prompt = build_prompt(chunk, file_path)

                # 1) DeepCode
                resp_dc = request_llm(DEEPCODE_MODEL_NAME, prompt)
                dc_findings = parse_llm_findings(resp_dc, file_path)
                partial_dc = load_partial_findings(PARTIAL_DC)
                partial_dc.extend(dc_findings)
                save_partial_findings(PARTIAL_DC, partial_dc)

                # 2) DeepSeek
                resp_ds = request_llm(DEEPSEEK_MODEL_NAME, prompt)
                ds_findings = parse_llm_findings(resp_ds, file_path)
                partial_ds = load_partial_findings(PARTIAL_DS)
                partial_ds.extend(ds_findings)
                save_partial_findings(PARTIAL_DS, partial_ds)

                # 3) StarCoder
                resp_sc = request_llm(STARCODER_MODEL_NAME, prompt)
                sc_findings = parse_llm_findings(resp_sc, file_path)
                partial_sc = load_partial_findings(PARTIAL_SC)
                partial_sc.extend(sc_findings)
                save_partial_findings(PARTIAL_SC, partial_sc)

                # 4) LLaMA
                resp_ll = request_llm(LLAMA_MODEL_NAME, prompt)
                ll_findings = parse_llm_findings(resp_ll, file_path)
                partial_ll = load_partial_findings(PARTIAL_LL)
                partial_ll.extend(ll_findings)
                save_partial_findings(PARTIAL_LL, partial_ll)

    # Done scanning all; finalize
    finalize_reports(total_files_scanned)
    sys.exit(0)

if __name__ == "__main__":
    main()
