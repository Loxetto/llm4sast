#!/usr/bin/env python3
import os
import sys
import json
import requests

# ------------------------------------------------------------------------
# 1) CONFIGURATIONS
# ------------------------------------------------------------------------
LLM_SERVER_URL = "http://127.0.0.1:1234/v1/completions"  # LM Studio Endpoint (example)
CODE_DIR = "../src"

CHUNK_SIZE = 150       # Number of lines per chunk
N_PREDICT = 4096       # max_tokens
TEMPERATURE = 0.2

SEM_GREP_REPORT_PATH = "reports/semgrep_report.json"
SONARQUBE_REPORT_PATH = "reports/sonarqube_report.json"

MAX_RETRIES = 3        # Number of retry attempts if the response is truncated / unparseable

# ------------------------------------------------------------------------
# 2) SUPPORTING FUNCTIONS
# ------------------------------------------------------------------------
def load_json_file(path: str) -> dict:
    """Load a JSON file. If it does not exist or is invalid, return {}."""
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"[WARN] Failed to load or parse JSON file: {path}. Treating as empty.")
            return {}
    return {}

def build_prompt(data_str: str, file_path: str) -> str:
    """
    Build the strict prompt, including the chunk of code (data_str),
    and ask for a strict JSON output with 'findings'.
    """
    prompt = f"""
You are a data-sensitive detection LLM used in a Git pre-commit hook.

RULES:
1) Output ONLY valid JSON with a top-level "findings" array.
2) Each object in the "findings" array must have the following keys:
   - "file_path" (string): The path of the file containing the issue.
   - "line" (string or number): The line number where the issue was found.
   - "message" (string): A description of the issue found.
   - "severity" (string): The severity of the issue, such as "error" or "warning".
3) Do NOT include any extra text, explanations, or code.
4) Stay within 4096 tokens if possible. If the response is too long, truncate the output to stay below this limit.
5) If no issues are found, return an empty "findings" array, like this:
   {{ "findings": [] }}
6) Do not generate any code or models. Focus only on identifying sensitive data issues or vulnerabilities within the provided chunk of code.
7) Analyze the following chunk of code (provided below), and combine it with the SAST reports from Semgrep and SonarQube.

DATA:
{data_str}

Remember: give me the issues only with a json, the entire output should be a json, with a top-level "findings" array. No extra text, explanations, or code.
"""
    return prompt.strip()

def request_llm(payload: dict) -> dict:
    """
    Sends a POST request to the LLM server with the given payload.
    Retries up to MAX_RETRIES times if the response is invalid or truncated.
    Returns the final JSON response as a dict.
    NOTE: No timeout is specified; it will wait indefinitely for a response.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # No 'timeout' parameter here, so it will wait indefinitely
            response = requests.post(LLM_SERVER_URL, json=payload)
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Connection error to LLM (Attempt {attempt}/{MAX_RETRIES}): {e}")
            if attempt == MAX_RETRIES:
                raise RuntimeError("Max retries reached. Unable to connect to LLM.")
            continue  # Retry

        if response.status_code != 200:
            print(f"[ERROR] LLM server responded with status {response.status_code} (Attempt {attempt}/{MAX_RETRIES}).")
            if attempt == MAX_RETRIES:
                raise RuntimeError(f"LLM server error: {response.text}")
            continue  # Retry

        try:
            resp_json = response.json()
        except json.JSONDecodeError:
            print(f"[WARN] Invalid JSON response from LLM (Attempt {attempt}/{MAX_RETRIES}).")
            if attempt == MAX_RETRIES:
                raise RuntimeError("Max retries reached. LLM response is not valid JSON.")
            continue  # Retry

        # Attempt to extract text from an OpenAI-like structure
        # If your server doesn't return 'choices', adapt as needed
        choices = resp_json.get("choices", [])
        if choices and "text" in choices[0]:
            content = choices[0]["text"]
        else:
            # If there's no 'text' or no 'choices', consider the entire response or adapt
            content = json.dumps(resp_json)

        if not content:
            print(f"[WARN] Empty response from LLM (Attempt {attempt}/{MAX_RETRIES}).")
            if attempt == MAX_RETRIES:
                raise RuntimeError("Max retries reached. LLM response is empty.")
            continue  # Retry

        # Try to parse the content as JSON
        try:
            final_json = json.loads(content)
            return final_json  # Successful response
        except json.JSONDecodeError:
            print(f"[WARN] LLM output is not pure JSON (Attempt {attempt}/{MAX_RETRIES}).")
            if attempt == MAX_RETRIES:
                raise RuntimeError("Max retries reached. LLM output is not valid JSON.")
            continue  # Retry

    # If all retries fail, raise an error
    raise RuntimeError("Failed to get a valid response from LLM after multiple attempts.")

def analyze_chunk(file_path: str, chunk_content: str, semgrep_report: dict, sonarqube_report: dict) -> list:
    """
    Analyzes a single chunk of code:
      1) Creates { "code": {file_path: chunk_content }, "semgrep":..., "sonarqube":... }
      2) Builds the prompt
      3) Sends the request to the LLM
      4) Verifies that .findings is a list
      5) Returns findings
      6) Raises RuntimeError if the response is invalid
    """
    combined_input = {
        "code": {file_path: chunk_content},
        "semgrep": semgrep_report,
        "sonarqube": sonarqube_report
    }

    data_str = json.dumps(combined_input, ensure_ascii=False)
    prompt = build_prompt(data_str, file_path)

    # Build the payload for /v1/completions (OpenAI-like style)
    payload = {
        "prompt": prompt,
        "max_tokens": N_PREDICT,
        "temperature": TEMPERATURE,
        "top_p": 0.9,
        "top_k": 40,
        "repeat_last_n": 64,
        "repeat_penalty": 1.2
    }

    # Send the request with retries
    final_json = request_llm(payload)

    # Extract findings
    findings = final_json.get("findings", [])

    if not isinstance(findings, list):
        raise RuntimeError("Field 'findings' is not a list in the returned JSON.")

    return findings

# ------------------------------------------------------------------------
# 3) MAIN FUNCTION TO PROCESS ALL CHUNKS
# ------------------------------------------------------------------------
def main():
    # Load SAST reports
    semgrep_report = load_json_file(SEM_GREP_REPORT_PATH)
    sonarqube_report = load_json_file(SONARQUBE_REPORT_PATH)

    # Check if CODE_DIR exists
    if not os.path.isdir(CODE_DIR):
        print(f"[INFO] Folder '{CODE_DIR}' not found. No files to analyze.")
        sys.exit(0)

    any_findings = False  # Flag to track if any issues are found

    # Traverse files in CODE_DIR
    for root, dirs, files in os.walk(CODE_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            print("=================================================")
            print(f"Analyzing file: {file_path}")

            # Read the file line by line
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError as e:
                print(f"[ERROR] Unable to read '{file_path}': {e}")
                sys.exit(1)

            total_lines = len(lines)
            if total_lines == 0:
                print(f"[INFO] Empty file: {file_path}")
                continue  # Skip empty files

            # Split the file content into chunks of CHUNK_SIZE lines
            chunks = [lines[i:i + CHUNK_SIZE] for i in range(0, len(lines), CHUNK_SIZE)]

            for chunk_index, chunk_lines in enumerate(chunks, start=1):
                # Join the lines of the chunk into a single string
                chunk_content = ''.join(chunk_lines)
                start_line = (chunk_index - 1) * CHUNK_SIZE + 1
                end_line = min(chunk_index * CHUNK_SIZE, total_lines)
                print(f" -> Chunk #{chunk_index} (lines {start_line}-{end_line} of {total_lines})")

                try:
                    findings = analyze_chunk(
                        file_path=file_path,
                        chunk_content=chunk_content,
                        semgrep_report=semgrep_report,
                        sonarqube_report=sonarqube_report
                    )
                except RuntimeError as e:
                    print(f"[ERROR] {e}")
                    sys.exit(1)  # Block the commit

                if findings:
                    print(f"[BLOCK] Issues found in chunk #{chunk_index} of '{file_path}':")
                    print(json.dumps(findings, indent=2, ensure_ascii=False))
                    any_findings = True
                    # Uncomment the next line to block immediately upon finding issues
                    # sys.exit(1)

    # After analyzing all files and chunks
    if any_findings:
        print("[BLOCK] Sensitive data or vulnerabilities found. Commit blocked.")
        sys.exit(1)
    else:
        print("[OK] No issues found in all chunks. Commit proceeds.")
        sys.exit(0)

if __name__ == "__main__":
    main()
