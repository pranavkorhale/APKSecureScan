import json
import os
import re
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from dotenv import load_dotenv
from groq import Groq

# === Load .env ===
load_dotenv()

# === Configuration ===
MOBSF_JSON_PATH = "./output_files/mobsf_report.json"
SUSI_SOURCES_PATH = "./sources sinks/Ouput_CatSources_v0_9.txt"
SUSI_SINKS_PATH = "./sources sinks/Ouput_CatSinks_v0_9.txt"
INTERMEDIATE_OUTPUT = "./output_files/suspicious_summary.txt"
FINAL_REPORT_PATH = "./output_files/malware_report.json"
CHUNK_SIZE = 150
MODEL_NAME = "llama3-70b-8192"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# === Groq Client Init ===
client = Groq(api_key=GROQ_API_KEY)

def safe_json_load(s: Optional[str]) -> Optional[dict]:
    try:
        return json.loads(s) if s else None
    except Exception as e:
        print(f"⚠️ Failed to parse JSON:\n{s}\nError: {e}")
        return None

def parse_susi_methods_only(file_path: str, typ: str) -> Dict[str, str]:
    methods = {}
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return methods

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            line = line.strip()
            if line.startswith("<") and ">" in line:
                match = re.search(r'<(.+?):\s.*?\s(\w+)\(.*\)>', line)
                if match:
                    method_name = match.group(2).lower()
                    if len(method_name) > 2:
                        methods[method_name] = typ
    return methods

def load_mobsf_api_sections(report_path: str) -> List[Tuple[str, str]]:
    with open(report_path, 'r') as f:
        data = json.load(f)
    entries = []
    android_api = data.get("android_api", {})
    for category, detail in android_api.items():
        for filepath in detail.get("files", {}):
            entries.append((category.lower(), filepath.lower()))
    return entries

def fuzzy_match(mobsf_entries: List[Tuple[str, str]], susi_methods: Dict[str, str]) -> List[Tuple[str, str, str]]:
    matches = []
    for category, path in mobsf_entries:
        for method, typ in susi_methods.items():
            if method in category or method in path:
                matches.append((typ, category, path))
    return matches

def generate_suspicious_summary(matches: List[Tuple[str, str, str]], output_path: str) -> Dict[Tuple[str, str], Dict[str, int]]:
    summary = defaultdict(lambda: {"source": 0, "sink": 0})
    for typ, category, path in matches:
        summary[(category, path)][typ] += 1

    with open(output_path, "w") as f:
        for (category, path), counts in summary.items():
            if counts["source"] > 0 or counts["sink"] > 0:
                line = f"- File: {path} | Category: {category} → Sources: {counts['source']}, Sinks: {counts['sink']}"
                f.write(line + "\n")

    return summary

def load_and_chunk_files(input_path: str, chunk_size: int = 50) -> List[str]:
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    return ["\n".join(lines[i:i + chunk_size]) for i in range(0, len(lines), chunk_size)]

def call_groq_llm(prompt: str) -> Optional[str]:
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=700
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"API Error: {e}")
        return None

def analyze_with_llm_with_retry(prompt: str, retries=3) -> Optional[str]:
    for attempt in range(retries):
        result = call_groq_llm(prompt)
        if result:
            return result
        wait = 2 ** attempt
        print(f"⏳ Retrying in {wait} seconds...")
        time.sleep(wait)
    return None

def build_analysis_prompt(chunk_text: str) -> str:
    return f"""
You are a senior Android malware analyst. Analyze this static code summary for potential threats.

Please examine the behavior of the app and provide a DETAILED assessment, considering:

- Usage of sensitive APIs (sources/sinks)
- Reflection, dynamic loading, obfuscation
- Data exfiltration or command-and-control (C2) behavior
- Privacy violations or system access abuse

Respond ONLY with a valid JSON object in this format:

{{
  "risk_level": "low" | "medium" | "high",
  "risk_type": ["obfuscation", "data_leak", "c2_behavior", "privilege_abuse", "..."],
  "key_indicators": [
    "DexClassLoader used with encrypted path",
    "SMS read and send permissions together",
    "Reflection used in native method invocation"
  ],
  "summary": "A few lines summarizing why this chunk is risky or not",
  "next_steps": [
    "Review obfuscated method chains in com.example.a.b",
    "Check for encrypted network traffic endpoints",
    "Correlate with dynamic analysis results"
  ]
}}

Do NOT add any commentary outside the JSON. Focus on being concise but precise.

Code under analysis:
{chunk_text}
""".strip()

def generate_final_report(results: List[str]) -> Dict:
    parsed_results = [safe_json_load(r) for r in results if r]
    parsed_results = [r for r in parsed_results if r]

    report = {
        "statistics": {
            "total_chunks": len(results),
            "high_risk": sum(1 for r in parsed_results if r.get("risk_level") == "high"),
            "medium_risk": sum(1 for r in parsed_results if r.get("risk_level") == "medium")
        },
        "detailed_findings": parsed_results,
        "executive_summary": None
    }

    if parsed_results:
        top_indicators = "\n".join(
            r['key_indicators'][0] for r in parsed_results if r["risk_level"] in ["high", "medium"]
        )

        summary_prompt = f"""
        You are a senior Android malware analyst.

        Based on the risk assessment findings below, generate a **detailed summary** of the threats identified. Your output should be:

        - A clear **bullet-point list** (5–10 points)
        - Each point should explain the specific risk, source/sink usage, and any suspicious behavior.
        - Highlight use of reflection, dynamic code loading, obfuscation, and potential data exfiltration.
        - End with 2 suggestions for further manual review.

        Do NOT include JSON or metadata. Just the summary in bullet format.

        Statistics:
        {json.dumps(report['statistics'], indent=2)}

        Key Indicators:
        {top_indicators}
        """.strip()


        summary = analyze_with_llm_with_retry(summary_prompt)
        report['executive_summary'] = summary
    else:
        print("⚠️ No valid results to summarize.")

    return report

def main():
    print("=== ANDROID SENSITIVE API ANALYSIS TOOL ===")

    print("\n[1/3] Static Analysis using SuSi + MobSF...")
    susi_methods = {}
    susi_methods.update(parse_susi_methods_only(SUSI_SOURCES_PATH, "source"))
    susi_methods.update(parse_susi_methods_only(SUSI_SINKS_PATH, "sink"))
    print(f" → Loaded {len(susi_methods)} SuSi methods")

    mobsf_entries = load_mobsf_api_sections(MOBSF_JSON_PATH)
    print(f" → Found {len(mobsf_entries)} MobSF behavior entries")

    matches = fuzzy_match(mobsf_entries, susi_methods)
    generate_suspicious_summary(matches, INTERMEDIATE_OUTPUT)

    print("\n[2/3] Running LLM Risk Assessment...")
    chunks = load_and_chunk_files(INTERMEDIATE_OUTPUT, CHUNK_SIZE)
    results = []

    for i, chunk in enumerate(chunks, 1):
        print(f"  ↪ Chunk {i}/{len(chunks)}")
        prompt = build_analysis_prompt(chunk)
        result = analyze_with_llm_with_retry(prompt)
        if result:
            results.append(result)
        time.sleep(1.5)


    print("\n[3/3] Generating Final Report...")
    final_report = generate_final_report(results)

    with open(FINAL_REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(final_report, f, indent=2)


    print("\n📋 Executive Summary:")
    print(final_report["executive_summary"] or "No summary available.")

if __name__ == "__main__":
    main()
