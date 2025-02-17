#!/usr/bin/env python3
import os
import sys
import json
import re
import argparse
import requests
import asyncio

try:
    import tiktoken
except ImportError:
    tiktoken = None
    print("[WARN] 'tiktoken' not installed. Will use approximate token counting fallback.")

# -------------------------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------------------------
DEBUG = True

# LM STUDIO single endpoint
LM_STUDIO_URL = "http://127.0.0.1:1234/v1/completions"  # Adjust as needed

# Dictionary of *all* possible models you might want to use:
# Key = an identifier, Value = the model name in LM Studio
ALL_AVAILABLE_MODELS = {
    "deepcode":  "deepcode-7b-aurora-v13",
    "deepseek":  "deepseek-coder-v2-lite-instruct",
    "starcoder": "dolphincoder-starcoder2-7b",
    "llama8B":     "meta-llama-3.1-8b-instruct",
    "llama3B":     "llama-3.2-3b-instruct"
}

# The code directory to scan
CODE_DIR = "../src/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode_low"

# Where partial/final files are stored
PARTIAL_PREFIX = "partial_findings_"
FINAL_JSON_PATH = "final_report.json"

# Token constraints
MAX_TOKENS = 4096
RESERVED_TOKENS = 500
N_PREDICT = 1024

# We only scan these file extensions
TEXT_FILE_EXTENSIONS = {".java", ".js"}

# Maximum concurrent requests
MAX_CONCURRENT_REQUESTS = 10

# -------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------------------------------
def debug_print(msg: str):
    if DEBUG:
        print(f"[DEBUG] {msg}")

def load_partial_findings(file_path: str) -> list:
    if not os.path.isfile(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("findings", [])
    except (json.JSONDecodeError, OSError):
        return []

def save_partial_findings(file_path: str, findings_list: list):
    data = {"findings": findings_list}
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

async def request_llm(session, model_name: str, prompt: str) -> dict:
    """
    POST to LM Studio with the specified 'model' field in the JSON body.
    """
    payload = {
        "model": model_name,
        "prompt": prompt,
        "max_tokens": N_PREDICT,
        "temperature": 0.2
    }

    debug_print(f"Sending async request to model={model_name}")

    try:
        async with session.post(LM_STUDIO_URL, json=payload) as response:
            response.raise_for_status()
            return await response.json()
    except Exception as e:
        print(f"[ERROR] Request to {LM_STUDIO_URL} failed: {e}")
        return {}

async def process_code_chunk(session, model_key: str, chunk: str, file_path: str):
    """Process a single code chunk with a given model asynchronously."""
    model_name = ALL_AVAILABLE_MODELS[model_key]
    prompt = f"Analyze the following code for security vulnerabilities:\n\n{chunk}"  # Placeholder prompt
    response = await request_llm(session, model_name, prompt)
    new_findings = response.get("choices", [])  # Adjust based on actual response format

    if new_findings:
        partial_path = PARTIAL_PREFIX + model_key + ".json"
        existing = load_partial_findings(partial_path)
        existing.extend(new_findings)
        save_partial_findings(partial_path, existing)
        debug_print(f"[INFO] Model={model_key} found {len(new_findings)} issues => partial updated.")

async def main():
    parser = argparse.ArgumentParser(description="Scan code with chosen LLM models in LM Studio.")
    parser.add_argument("--models", type=str, default="deepcode,deepseek",
                        help="Comma-separated list of model keys to use (e.g. deepcode,deepseek,starcoder,llama).")
    args = parser.parse_args()

    models_chosen = [m.strip() for m in args.models.split(",") if m.strip()]
    for m in models_chosen:
        if m not in ALL_AVAILABLE_MODELS:
            print(f"[ERROR] Unknown model key: {m}. Allowed: {list(ALL_AVAILABLE_MODELS.keys())}")
            sys.exit(1)

    for m in models_chosen:
        file_path = PARTIAL_PREFIX + m + ".json"
        save_partial_findings(file_path, [])

    if not os.path.isdir(CODE_DIR):
        print(f"[ERROR] Code directory '{CODE_DIR}' not found.")
        sys.exit(1)

    total_files_scanned = 0
    tasks = []

    import aiohttp
    async with aiohttp.ClientSession() as session:
        for root, _, files in os.walk(CODE_DIR):
            for filename in files:
                file_path = os.path.join(root, filename)
                if os.path.splitext(file_path)[1].lower() not in TEXT_FILE_EXTENSIONS:
                    continue
                total_files_scanned += 1
                debug_print(f"Processing file: {file_path}")
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    code_content = f.read()
                for model_key in models_chosen:
                    tasks.append(process_code_chunk(session, model_key, code_content, file_path))
                if len(tasks) >= MAX_CONCURRENT_REQUESTS:
                    await asyncio.gather(*tasks)
                    tasks = []
        if tasks:
            await asyncio.gather(*tasks)

    print("[OK] Analysis complete!")

if __name__ == "__main__":
    asyncio.run(main())
