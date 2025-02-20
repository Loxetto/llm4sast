import json
import os

# Mappa di corrispondenza tra le category di expectedResults (es: "pathtraver") e l'enum desiderato (es: "Path Traversal")
CATEGORY_TO_ENUM = {
    "cmdi": "Command Injection",
    "crypto": "Weak Encryption",
    "hash": "Weak Hashing",
    "ldapi": "LDAP Injection",
    "pathtraver": "Path Traversal",
    "securecookie": "Insecure Cookie",
    "sqli": "SQL Injection",
    "trustbound": "Trust Boundary",
    "weakrand": "Weak Randomness",
    "xpathi": "XPath Injection",
    "xss": "Cross Site Scripting"
}

AGGREGATED_FINDINGS_PATH = "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/scripts/aggregated_findings.json"
EXPECTED_RESULTS_PATH = "C:/Users/loxru/OneDrive/Documenti/UNI/TESI/PROVA/src/BenchmarkJava/expectedResults.json"
OUTPUT_COMPARE_PATH = "compare_summary.json"

def load_json(file_path):
    """Carica un file JSON da disco."""
    if not os.path.isfile(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def compare_final_results():
    """
    Confronta aggregated_findings.json (uno per file, con array di vulnerability_types)
    con expectedResults.json (che definisce se per un test name esiste una vuln "reale").

    Calcoliamo TP, FP, FN, TN per ogni categoria dell'enum, aggregando i risultati.
    """

    # Carica i dati
    aggregated_data = load_json(AGGREGATED_FINDINGS_PATH)  # { "files": [ { "file": "...", "vulnerability_types": [] }, ... ] }
    expected_list = load_json(EXPECTED_RESULTS_PATH)       # [ { "# test name": "...", "category": "...", "real vulnerability": bool }, ... ]

    # Se non troviamo la chiave "files", interrompiamo
    if "files" not in aggregated_data:
        print("[ERRORE] Il JSON aggregato non contiene la chiave 'files'.")
        return

    # 1) Creiamo un map di expected => { "BenchmarkTest00001": { "category": "Path Traversal", "real": True/False } }
    expected_map = {}
    for item in expected_list:
        test_name = item.get("# test name", "").strip()
        raw_cat = item.get("category", "").strip()
        is_real = item.get("real vulnerability", False)
        if not test_name or not raw_cat:
            continue

        # Mappiamo la category: es. "pathtraver" -> "Path Traversal"
        mapped_cat = CATEGORY_TO_ENUM.get(raw_cat, raw_cat)

        # Memorizziamo (ipotizzando un'unica vuln per file).
        # Se esistono più righe per lo stesso test_name nel JSON, sovrascriverà. 
        # Se invece devi gestire più di una vulnerabilità "reale" per lo stesso file, 
        # dovresti usare una lista. (Per OWASP Benchmark, di solito c'è 1 category principale.)
        expected_map[test_name] = {
            "category": mapped_cat,
            "real": is_real
        }

    # 2) Creiamo un map di aggregator => { "BenchmarkTest00001": ["Path Traversal", "SQL Injection", ...], ... }
    found_map = {}
    for fdata in aggregated_data["files"]:
        test_name = fdata["file"]  # es. "BenchmarkTest00001"
        vuln_types = fdata["vulnerability_types"]  # es. ["Path Traversal", "Command Injection"]
        # Salviamo
        found_map[test_name] = vuln_types

    # 3) Creiamo delle strutture per calcolare i totali (TP, FP, FN, TN) per ogni categoria
    # Ad es.: results_by_category = { "Path Traversal": { "TP": 0, "FP": 0, "FN": 0, "TN": 0 }, ... }
    results_by_category = {}

    def ensure_cat(cat):
        if cat not in results_by_category:
            results_by_category[cat] = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

    # 4) Confronto: per ogni test_name in expected_map
    #    Se c'è una riga in found_map, vediamo se la category attesa è dentro found_map[test_name].
    #    In base a real: True o False, decidiamo se è TP, FP, FN, TN.
    all_test_names = set(expected_map.keys()).union(set(found_map.keys()))

    for test_name in all_test_names:
        einfo = expected_map.get(test_name)
        finfo = found_map.get(test_name, [])

        if not einfo:
            # Se NON c'è in expected_map, non sappiamo che cat era attesa => nessuna vulnerabilità definita
            # potremmo considerare ogni vuln trovata come "FP" per la relativa category?
            for cat_found in finfo:
                ensure_cat(cat_found)
                results_by_category[cat_found]["FP"] += 1
            continue

        # Altrimenti, abbiamo category attesa e real
        expected_cat = einfo["category"]
        is_real = einfo["real"]
        ensure_cat(expected_cat)

        # Se la category attesa è stata trovata nel found_map
        if expected_cat in finfo:
            # => segnalazione su category attesa
            if is_real:
                # True Positive
                results_by_category[expected_cat]["TP"] += 1
            else:
                # False Positive
                results_by_category[expected_cat]["FP"] += 1
        else:
            # => category attesa NON trovata
            if is_real:
                # False Negative
                results_by_category[expected_cat]["FN"] += 1
            else:
                # True Negative
                results_by_category[expected_cat]["TN"] += 1

        # Infine, se nel found_map[test_name] ci sono altre category diverse da expected_cat,
        # e non appaiono in expectedResults, contano come FP (perché non era una vuln attesa)
        for cat_found in finfo:
            if cat_found == expected_cat:
                continue  # già gestita sopra
            # Non era attesa questa cat, quindi se einfo dice real=False per questa cat,
            # in senso stretto è un FP (perché la stiamo segnalando e non era "prevista").
            ensure_cat(cat_found)
            # In un test-case OWASP standard, c'è 1 category per file. Se il modello ne trova di più,
            # consideriamo "FP" su quelle extra (non menzionate in expected).
            results_by_category[cat_found]["FP"] += 1

    # 5) Calcoliamo un output finale con TP, FP, FN, TN e percentuali
    summary = {}
    for cat, vals in results_by_category.items():
        tp = vals["TP"]
        fp = vals["FP"]
        fn = vals["FN"]
        tn = vals["TN"]
        total = tp + fp + fn + tn
        if total > 0:
            tp_perc = round((tp / total) * 100, 2)
            fp_perc = round((fp / total) * 100, 2)
            fn_perc = round((fn / total) * 100, 2)
            tn_perc = round((tn / total) * 100, 2)
        else:
            tp_perc = fp_perc = fn_perc = tn_perc = 0

        summary[cat] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "TP_percent": tp_perc,
            "FP_percent": fp_perc,
            "FN_percent": fn_perc,
            "TN_percent": tn_perc
        }

    # 6) Salviamo i risultati
    with open(OUTPUT_COMPARE_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Confronto completato. Risultati salvati in {OUTPUT_COMPARE_PATH}")

if __name__ == "__main__":
    compare_final_results()
