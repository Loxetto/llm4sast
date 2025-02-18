import json
from collections import defaultdict

def merge_issues(issues):
    """
    Raggruppa le issue per file (campo "component") e linea (campo "line")
    e aggrega le informazioni chiave (messaggi, gravità, regole, tag e tipo).
    """
    groups = defaultdict(lambda: {
        "file_path": None,
        "line": None,
        "messages": set(),
        "severity": set(),
        "rules": set(),
        "tags": set(),
        "types": set()
    })
    
    for issue in issues:
        key = (issue.get("component", ""), str(issue.get("line", "")))
        group = groups[key]
        group["file_path"] = issue.get("component", "")
        group["line"] = str(issue.get("line", ""))
        if issue.get("message"):
            group["messages"].add(issue["message"])
        if issue.get("severity"):
            group["severity"].add(issue["severity"])
        if issue.get("rule"):
            group["rules"].add(issue["rule"])
        if issue.get("tags"):
            for tag in issue.get("tags"):
                group["tags"].add(tag)
        if issue.get("type"):
            group["types"].add(issue["type"])
    
    deduped = []
    for (file_path, line), group in groups.items():
        deduped.append({
            "file_path": group["file_path"],
            "line": group["line"],
            "messages": list(group["messages"]),
            "severity": ", ".join(group["severity"]),
            "rules": list(group["rules"]),
            "tags": list(group["tags"]),
            "types": ", ".join(group["types"])
        })
    return deduped

def main():
    input_file = "reports/sonarqube_report.json"
    output_file = "reports/deduped_report.json"
    
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Legge le issue dalla chiave "issues"
    issues = data.get("issues", [])
    deduped = merge_issues(issues)
    
    deduped_report = {
        "total_issues": data.get("total", len(issues)),
        "deduped_issues": deduped
    }
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(deduped_report, f, indent=2)
    
    print(f"Deduped report saved to {output_file}")

if __name__ == "__main__":
    main()
