#!/usr/bin/env python3
import json

SEM_GREP_INPUT = "reports/semgrep_report.json"
SEM_GREP_OUTPUT = "reports/semgrep_report_min.json"

def main():
    with open(SEM_GREP_INPUT, "r", encoding="utf-8") as f:
        data = json.load(f)

    # We'll store only the minimal relevant fields
    minimal_results = []

    # The semgrep data is typically in data["results"]
    for item in data.get("results", []):
        check_id = item.get("check_id", "")
        path = item.get("path", "")
        start_line = item.get("start", {}).get("line", 0)
        severity = item.get("severity", "")
        
        # The user-facing message is in item["extra"]["message"] usually
        message = item.get("extra", {}).get("message", "")
        
        # Some rules provide CWE(s) in item["extra"]["metadata"]["cwe"]
        # It's often an array like ["CWE-352: Cross-Site Request Forgery (CSRF)"]
        cwe_list = item.get("extra", {}).get("metadata", {}).get("cwe", [])
        
        # Example: we only keep the CWE IDs themselves, or the entire string
        # We'll store them as a list of short IDs (like "CWE-352", "CWE-22", etc.)
        # We might do a little cleanup:
        cwe_cleaned = []
        for c in cwe_list:
            # Some c might be "CWE-352: Cross-Site Request Forgery (CSRF)"
            # We'll keep just "CWE-352"
            c_split = c.split(":")[0].strip()
            cwe_cleaned.append(c_split)

        minimal_results.append({
            "check_id": check_id,
            "path": path,
            "line": start_line,
            "severity": severity,
            "message": message,
            "cwe": cwe_cleaned
        })

    # Wrap these minimal results
    output_data = {
        "results": minimal_results
    }

    with open(SEM_GREP_OUTPUT, "w", encoding="utf-8") as out:
        json.dump(output_data, out, indent=2, ensure_ascii=False)

    print(f"[OK] Created minimal Semgrep JSON => {SEM_GREP_OUTPUT}")
    print(f"Reduced from {len(data.get('results', []))} items to {len(minimal_results)} minimal items.")

if __name__ == "__main__":
    main()
