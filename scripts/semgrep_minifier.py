#!/usr/bin/env python3
import json
from collections import defaultdict

SEM_GREP_INPUT = "reports/semgrep_report.json"
SEM_GREP_OUTPUT = "reports/semgrep_report_min.json"

def main():
    with open(SEM_GREP_INPUT, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Dictionary to group findings by (path, message)
    aggregated_findings = defaultdict(lambda: {"check_id": [], "severity": "", "cwe": []})
    
    for item in data.get("results", []):
        check_id = item.get("check_id", "")
        path = item.get("path", "")
        start_line = item.get("start", {}).get("line", 0)
        severity = item.get("severity", "")
        message = item.get("extra", {}).get("message", "")
        
        # Extract and clean CWE identifiers
        cwe_list = item.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe_cleaned = [c.split(":")[0].strip() for c in cwe_list]
        
        key = (path, message)  # Unique key for grouping findings
        
        # Append check_id and update severity and CWE if not already present
        if check_id not in aggregated_findings[key]["check_id"]:
            aggregated_findings[key]["check_id"].append(check_id)
        
        aggregated_findings[key]["severity"] = severity  # Assume same severity for grouped findings
        
        for cwe in cwe_cleaned:
            if cwe not in aggregated_findings[key]["cwe"]:
                aggregated_findings[key]["cwe"].append(cwe)
    
    # Convert aggregated findings into the desired output format
    minimal_results = []
    for (path, message), values in aggregated_findings.items():
        minimal_results.append({
            "path": path,
            "message": message,
            "check_id": values["check_id"],
            "severity": values["severity"],
            "cwe": values["cwe"]
        })
    
    # Wrap and save the output
    output_data = {"results": minimal_results}
    with open(SEM_GREP_OUTPUT, "w", encoding="utf-8") as out:
        json.dump(output_data, out, indent=2, ensure_ascii=False)
    
    print(f"[OK] Created minimal Semgrep JSON => {SEM_GREP_OUTPUT}")
    print(f"Reduced from {len(data.get('results', []))} items to {len(minimal_results)} aggregated items.")

if __name__ == "__main__":
    main()
