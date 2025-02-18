import json

def simplify_issue(issue):
    """
    Estrae i campi essenziali da una issue.
    Puoi modificare questa funzione per includere solo le informazioni
    ritenute veramente rilevanti per la tua analisi.
    """
    return {
        "file": issue.get("component", ""),
        "line": issue.get("line"),
        "severity": issue.get("severity", ""),
        "rule": issue.get("rule", ""),
        "message": issue.get("message", ""),
        "type": issue.get("type", ""),
        "tags": issue.get("tags", [])
    }

def main():
    input_file = "reports/sonarqube_report.json"
    output_file = "reports/sonarqube_report_min.json"
    
    # Carica il report originale
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    issues = data.get("issues", [])
    simplified_issues = [simplify_issue(issue) for issue in issues]
    
    simplified_report = {
        "total_issues": data.get("total", len(issues)),
        "issues": simplified_issues
    }
    
    # Salva il report semplificato
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(simplified_report, f, indent=2)
    
    print(f"Simplified report saved to {output_file}")

if __name__ == "__main__":
    main()
