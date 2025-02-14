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

LLM_SERVER_URL = "http://127.0.0.1:1234/v1/completions"  # Local model endpoint
CODE_DIR = "../src/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"  # The code directory to scan
MAX_TOKENS = 4096
RESERVED_TOKENS = 500
N_PREDICT = 1024

SEM_GREP_REPORT_PATH = "reports/semgrep_report.json"
SONARQUBE_REPORT_PATH = "reports/sonarqube_report.json"
MAX_SAST_TOKENS = 2000

# We only scan files with these extensions
TEXT_FILE_EXTENSIONS = {".java", ".js"}

# -------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------------------------------
def debug_print(msg: str):
    """Print debug messages if DEBUG is set to True."""
    if DEBUG:
        print(f"[DEBUG] {msg}")

def load_json_file(path: str) -> dict:
    """Load JSON file, returning an empty dict on error or if file not found."""
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"[WARN] Error loading {path}. Using empty dict.")
            return {}
    return {}

def approximate_token_count(text: str) -> int:
    """Fallback method that assumes ~4 characters per token."""
    return len(text) // 4

def count_tokens(text: str, model_name: str = "DeepSeek") -> int:
    """
    Count the number of tokens, falling back to approximate if needed.
    Adjust 'model_name' as needed if your tokenizer expects a different identifier.
    """
    if tiktoken is None:
        return approximate_token_count(text)
    try:
        encoding = tiktoken.encoding_for_model(model_name)
        return len(encoding.encode(text))
    except Exception:
        return approximate_token_count(text)

def chunk_text_by_tokens(text: str, available_tokens: int) -> list:
    """
    Splits the text into chunks so each chunk does not exceed the token budget.
    Chunking is done line-by-line, which is simple but might not be optimal if you have very long lines.
    """
    chunks = []
    current_lines = []
    current_token_count = 0

    lines = text.split("\n")
    for line in lines:
        line_token_count = count_tokens(line + "\n", model_name="DeepSeek")

        if current_token_count + line_token_count > available_tokens:
            chunks.append("\n".join(current_lines))
            current_lines = [line]
            current_token_count = line_token_count
        else:
            current_lines.append(line)
            current_token_count += line_token_count

    if current_lines:
        chunks.append("\n".join(current_lines))

    return chunks

def request_llm(prompt: str) -> dict:
    """
    Send the request to the local LLM server (DeepSeek or any OpenAI-style endpoint)
    and return the top-level JSON.
    """
    payload = {
        "prompt": prompt,
        "max_tokens": N_PREDICT,
        "temperature": 0.2
    }

    debug_print(f"Sending prompt to LLM (~{count_tokens(prompt, model_name='DeepSeek')} tokens)...")
    try:
        response = requests.post(LLM_SERVER_URL, json=payload)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to LLM server: {e}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"[ERROR] LLM server error {response.status_code}: {response.text}")
        sys.exit(1)

    try:
        return response.json()
    except json.JSONDecodeError:
        print("[ERROR] LLM server returned non-JSON response.")
        sys.exit(1)

def build_prompt(code_chunk: str, file_path: str, sast_reports: str) -> str:
    """
    Construct the prompt for the LLM, including SAST reports and code chunk.
    The LLM should return a JSON with a "findings" array, per the instructions below.
    """
    prompt = f"""
You are a security expert LLM for sensitive data detection in source code.
You will receive a code chunk along with the corresponding eventual SAST reports.

RULES:
1) Output ONLY valid JSON with a top-level "findings" array.
2) This is the JSON schema to follow:
{{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/security-findings-schema.json",
  "type": "object",
  "title": "Security Analysis Report",
  "description": "Represents a summary of security findings and associated metadata",
  "properties": {{
    "summary": {{
      "type": "object",
      "description": "High-level summary of the scan results",
      "properties": {{
        "status": {{
          "type": "string",
          "description": "Indicates if the scan completed successfully, or any relevant status."
        }},
        "files_scanned": {{
          "type": "integer",
          "description": "Number of source code files that were scanned."
        }},
        "total_vulnerabilities": {{
          "type": "integer",
          "description": "Total number of vulnerabilities found across all files."
        }},
        "percentage_files_affected": {{
          "type": "number",
          "description": "Percentage of scanned files that contained at least one vulnerability."
        }},
        "scan_timestamp": {{
          "type": "string",
          "format": "date-time",
          "description": "ISO 8601 timestamp indicating when the scan was performed."
        }}
      }},
      "required": [
        "status",
        "files_scanned",
        "total_vulnerabilities"
      ]
    }},
    "cwe_counts": {{
      "type": "object",
      "description": "Map of CWE IDs to the number of times they were identified in the findings.",
      "additionalProperties": {{
        "type": "integer"
      }}
    }},
    "findings": {{
      "type": "array",
      "description": "A list of individual vulnerability findings.",
      "items": {{
        "type": "object",
        "properties": {{
          "file_path": {{
            "type": "string",
            "description": "The path of the file containing the issue."
          }},
          "line": {{
            "type": [
              "integer",
              "string"
            ],
            "description": "The line number where the issue was found."
          }},
          "message": {{
            "type": "string",
            "description": "A description of the issue found."
          }},
          "severity": {{
            "type": "string",
            "enum": [
              "error",
              "warning",
              "info"
            ],
            "description": "The severity level of the issue."
          }},
          "cwe_ids": {{
            "type": "array",
            "description": "An optional list of CWE identifiers linked to this finding.",
            "items": {{
              "type": "string"
            }}
          }},
          "recommendation": {{
            "type": "string",
            "description": "Optional short guidance or remediation steps."
          }}
        }},
        "required": [
          "file_path",
          "line",
          "message",
          "severity"
        ]
      }}
    }}
  }},
  "required": [
    "summary",
    "findings"
  ]
}}
3) The response MUST NOT contain anything else than a valid JSON.
4) If no vulnerabilities are found, return:
   {{ "findings": [] }}
5) Do not generate any explanations, only the JSON result.
6) Your input includes a chunk of code and maybe SAST reports.

SAST REPORTS:
{sast_reports}

CODE CHUNK (file: {file_path}):
{code_chunk}
"""

    return prompt.strip()

def maybe_summarize_sast(semgrep_data: dict, sonarqube_data: dict) -> str:
    """
    Combine Semgrep + SonarQube data into a single JSON string.
    If too large, truncate (or selectively keep only high severity).
    """
    full_sast_json = {
        "semgrep": semgrep_data,
        "sonarqube": sonarqube_data
    }
    raw_sast_str = json.dumps(full_sast_json, ensure_ascii=False)
    tokens_count = count_tokens(raw_sast_str, model_name="DeepSeek")

    debug_print(f"SAST reports total token count: {tokens_count}")

    if tokens_count <= MAX_SAST_TOKENS:
        debug_print("SAST reports fit within MAX_SAST_TOKENS limit.")
        return raw_sast_str
    else:
        print("[WARN] SAST reports exceed token limit. Truncating them.")
        # Simple naive truncation
        return raw_sast_str[:5000] + "...(truncated)..."

def is_text_file(file_path: str) -> bool:
    """Check if the file extension is in the set of known text-based extensions."""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in TEXT_FILE_EXTENSIONS

def extract_cwe_from_message(message: str) -> list:
    """
    Naive approach to find any CWE references in the message (e.g. "CWE-79").
    Returns a list of matched CWE IDs.
    """
    pattern = r"(CWE-\d+)"
    return re.findall(pattern, message)

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    # 1. Load SAST data (Semgrep, SonarQube) and possibly summarize
    debug_print("Loading Semgrep report...")
    semgrep_report = load_json_file(SEM_GREP_REPORT_PATH)

    debug_print("Loading SonarQube report...")
    sonarqube_report = load_json_file(SONARQUBE_REPORT_PATH)

    debug_print("Possibly summarizing SAST data...")
    sast_reports_str = maybe_summarize_sast(semgrep_report, sonarqube_report)
    sast_tokens = count_tokens(sast_reports_str, model_name="DeepSeek")
    debug_print(f"Final SAST token count after summarize: {sast_tokens}")

    available_code_tokens = MAX_TOKENS - RESERVED_TOKENS - sast_tokens
    debug_print(f"Available tokens for code chunk: {available_code_tokens}")

    # If no space remains for code, skip scanning
    if available_code_tokens <= 0:
        print("[ERROR] SAST reports occupy too many tokens. No code scanned.")
        # Print a minimal JSON and exit with success
        result = {
            "summary": {
                "status": "No code scanned (SAST reports too large)",
                "files_scanned": 0,
                "total_vulnerabilities": 0
            },
            "vulnerabilities": []
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    # If the directory doesn't exist, no scanning
    if not os.path.isdir(CODE_DIR):
        print(f"[INFO] Directory '{CODE_DIR}' not found. No files to analyze.")
        result = {
            "summary": {
                "status": "No code directory found",
                "files_scanned": 0,
                "total_vulnerabilities": 0
            },
            "vulnerabilities": []
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    # 2. Prepare to collect all findings
    all_findings = []
    total_files_scanned = 0

    # 3. Walk through the code directory, scanning relevant files
    debug_print(f"Walking through code directory: {CODE_DIR}")
    for root, _, files in os.walk(CODE_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Filter by extension
            if not is_text_file(file_path):
                debug_print(f"Skipping non-text file: {file_path}")
                continue

            total_files_scanned += 1
            debug_print(f"Reading file: {file_path}")

            # Read the file content
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    code_content = f.read()
            except OSError as e:
                print(f"[ERROR] Cannot read '{file_path}': {e}")
                continue

            # Split the content into manageable chunks
            code_chunks = chunk_text_by_tokens(code_content, available_code_tokens)
            debug_print(f"File '{file_path}' split into {len(code_chunks)} chunk(s).")

            for chunk_idx, chunk in enumerate(code_chunks, start=1):
                chunk_token_count = count_tokens(chunk, model_name="DeepSeek")
                debug_print(f"Processing chunk {chunk_idx} for file '{file_path}' (~{chunk_token_count} tokens).")

                # Build the prompt and send to LLM
                prompt = build_prompt(chunk, file_path, sast_reports_str)
                outer_response = request_llm(prompt)  # The top-level response (OpenAI-like format)

                # DEBUG: Print partial for reference
                if DEBUG:
                    print("[DEBUG] LLM raw response (truncated):")
                    print(json.dumps(outer_response, indent=2)[:500] + "...")

                # Extract the actual JSON from choices[0]["text"]
                choices = outer_response.get("choices", [])
                if not choices:
                    # No completion returned
                    continue

                llm_raw_json_str = choices[0].get("text", "").strip()
                if not llm_raw_json_str:
                    continue

                # Attempt to parse the sub-JSON containing "findings"
                try:
                    llm_findings_obj = json.loads(llm_raw_json_str)
                    chunk_findings = llm_findings_obj.get("findings", [])
                except json.JSONDecodeError:
                    print(f"[WARN] The LLM returned invalid JSON for file {file_path} chunk {chunk_idx}.")
                    chunk_findings = []

                # Accumulate them into our global all_findings
                for item in chunk_findings:
                    # Make sure mandatory keys exist
                    fp = item.get("file_path", file_path)
                    ln = item.get("line", 0)
                    msg = item.get("message", "")
                    sev = item.get("severity", "info")

                    all_findings.append({
                        "file_path": fp,
                        "line": ln,
                        "message": msg,
                        "severity": sev
                    })

    # 4. Build summary
    total_vulns = len(all_findings)

    # Build a quick CWE frequency map from the "message" field
    cwe_map = {}
    for finding in all_findings:
        cwes = extract_cwe_from_message(finding["message"])
        for c in cwes:
            cwe_map[c] = cwe_map.get(c, 0) + 1

    # Example metric: % of files that had at least 1 vulnerability
    files_affected = {f["file_path"] for f in all_findings}
    percentage_files_affected = 0.0
    if total_files_scanned > 0:
        percentage_files_affected = (len(files_affected) / total_files_scanned) * 100

    # 5. Final JSON result
    result = {
        "summary": {
            "status": "Scan complete",
            "files_scanned": total_files_scanned,
            "total_vulnerabilities": total_vulns,
            "percentage_files_affected": round(percentage_files_affected, 2),
        },
        "cwe_counts": cwe_map,
        "vulnerabilities": all_findings
    }

    # Print final JSON to stdout and exit(0)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0)

# -------------------------------------------------------------------------
# SCRIPT ENTRY
# -------------------------------------------------------------------------
if __name__ == "__main__":
    main()
