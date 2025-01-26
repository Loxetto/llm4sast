#!/usr/bin/env bash

set -euo pipefail

# ----------------------------------------------------------------------
# 1. CONFIGURAZIONI
# ----------------------------------------------------------------------

LLM_SERVER_URL="http://127.0.0.1:1234/v1/completions"

# Facoltativo: percorsi dei report Semgrep e SonarQube
SEM_GREP_REPORT_PATH="reports/semgrep_report.json"
SONARQUBE_REPORT_PATH="reports/sonarqube_report.json"

# Parametri di generazione ridotti (es. 256 token massimi)
N_PREDICT="256"

# Prompt RIGIDO: specificare che va emesso SOLO JSON
BASE_PROMPT="
You are a data sensitive detection LLM, running in a Git pre-commit hook.
Analyze the provided code and SAST reports (from Semgrep and SonarQube) to detect:
 - secrets/credentials,
 - PII (personally identifiable information),
 - potential vulnerabilities.

IMPORTANT GUIDELINES:
1. Output **only** valid JSON, with a root object that has a key \"findings\", an array of objects.
2. No additional text, Markdown, explanations, or code blocks outside that JSON.
3. Each object in \"findings\" must contain:
   - \"file_path\" (string),
   - \"line\" (string or number),
   - \"message\" (string),
   - \"severity\" (string, e.g. \"warning\" or \"critical\").
4. If no issues are found, return {\"findings\": []}.
5. If issues are found, return them in \"findings\". The commit will be blocked for manual confirmation or fixes.

Any extraneous text outside this JSON object will cause an error.
"

# ----------------------------------------------------------------------
# 2. LETTURA DEI REPORT (o fallback a {})
# ----------------------------------------------------------------------
if [ -f "$SEM_GREP_REPORT_PATH" ]; then
  semgrep_report=$(jq '.' "$SEM_GREP_REPORT_PATH" 2>/dev/null || echo "{}")
else
  semgrep_report="{}"
fi

if [ -f "$SONARQUBE_REPORT_PATH" ]; then
  sonarqube_report=$(jq '.' "$SONARQUBE_REPORT_PATH" 2>/dev/null || echo "{}")
else
  sonarqube_report="{}"
fi

# ----------------------------------------------------------------------
# 3. CARTELLA CODICE
#    Esempio: ../src (puoi adattare)
# ----------------------------------------------------------------------
CODE_DIR="../src"
if [ ! -d "$CODE_DIR" ]; then
  echo "[INFO] No $CODE_DIR directory found. Skipping code analysis."
  exit 0
fi

# ----------------------------------------------------------------------
# 4. LOOP SU TUTTI I FILE IN ../src
# ----------------------------------------------------------------------
ANY_FINDINGS=0  # Flag per sapere se ci sono stati problemi

mkdir -p reports

for file in $(find "$CODE_DIR" -type f); do
  echo "Analyzing: $file"

  # Legge il contenuto del file
  code_content=$(<"$file")

  # JSON con un singolo file
  single_file_json=$(jq -n \
    --arg f "$file" \
    --arg c "$code_content" \
    '{ ($f): $c }'
  )

  # Combino i JSON (codice + report)
  combined_input=$(jq -n \
    --argjson code "$single_file_json" \
    --argjson sem "$semgrep_report" \
    --argjson son "$sonarqube_report" \
    '{
      "code": $code,
      "semgrep": $sem,
      "sonarqube": $son
    }'
  )

  # Unisco con prompt rigido
  full_prompt="$BASE_PROMPT\n\nDATA:\n$(echo "$combined_input" | jq -c .)"

  # Costruisco payload
  json_payload=$(jq -n \
    --arg prompt "$full_prompt" \
    --arg n_predict "$N_PREDICT" \
    '{
      prompt: $prompt,
      n_predict: ($n_predict|tonumber),
      temperature: 0.2,
      top_p: 0.9
    }'
  )

  # Invia la richiesta
  response=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "$json_payload" "$LLM_SERVER_URL")

  # Tenta di parseare TUTTA la risposta come JSON
  # Se il modello ha aggiunto testo extra, qui fallirà
  echo "$response" | jq '.' > "reports/llm_report_$(basename "$file" | sed 's/[^a-zA-Z0-9]/_/g').json" \
    || {
      echo "[ERROR] The model did not return strictly valid JSON. Blocking commit."
      exit 1
    }

  # Estraggo 'findings'
  findings=$(echo "$response" | jq '.findings' 2>/dev/null || echo "null")

  if [ "$findings" == "null" ]; then
    echo "[WARN] No 'findings' key found -> treat as no issues but might be an LLM format error."
    findings="[]"
  fi

  if [ "$findings" != "[]" ]; then
    echo "[ALERT] Issues found in $file => Blocking commit."
    echo "$findings" | jq .
    ANY_FINDINGS=1
    # Se vuoi bloccare subito, puoi fare: exit 1
  else
    echo "[OK] No issues for $file"
  fi

  echo "--------------------------------"
done

# Se in uno dei file abbiamo ANY_FINDINGS=1, esci con errore per bloccare il commit
if [ "$ANY_FINDINGS" -eq 1 ]; then
  echo "===> Detected sensitive data or vulnerabilities. Stopping commit."
  exit 1
else
  echo "===> No issues found in any file. Commit can proceed."
  exit 0
fi