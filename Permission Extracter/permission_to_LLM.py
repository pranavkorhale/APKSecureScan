import json
import os
import time
from dotenv import load_dotenv
from groq import Groq

# === Load environment variables ===
load_dotenv()

# === CONFIGURATION ===
MOBSF_REPORT_PATH = "./output_files/mobsf_report.json"
CHUNK_SIZE = 100
MODEL = "llama3-70b-8192"

# === Init Groq client ===
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# === STEP 1: Extract Permissions from MobSF JSON ===
def extract_permissions(json_path):
    try:
        with open(json_path, "r") as file:
            report = json.load(file)

        permissions_data = report.get("permissions", {})
        if not permissions_data:
            print("⚠️ No permissions found in the report.")
            return []

        permissions = [f"- {perm_name}" for perm_name in permissions_data.keys()]
        print(f"✅ Extracted {len(permissions)} permissions.")
        return permissions

    except FileNotFoundError:
        print(f"❌ Error: File not found — {json_path}")
        return []
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON in {json_path}")
        return []

# === STEP 2: Chunk the Permission List ===
def chunk_permissions(permissions, chunk_size=CHUNK_SIZE):
    return ["\n".join(permissions[i:i + chunk_size]) for i in range(0, len(permissions), chunk_size)]

# === STEP 3: Call Groq LLM with Retry ===
def call_groq_llm(prompt, retries=3):
    for attempt in range(retries):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1024
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"[!] Attempt {attempt + 1} failed: {e}")
            time.sleep(2)
    return None

# === STEP 4: Analyze One Chunk ===
def analyze_permission_chunk(chunk_text):
    prompt = f"""You are a mobile security analyst. Analyze the following Android app permissions from a security and privacy standpoint.

For each permission:
- Explain its purpose in simple terms.
- Analyze how it can be abused or misused.
- Determine if it's sensitive or overprivileged.

At the end, provide:
- A summary of risky combinations (e.g., Internet + SMS)
- An overall risk rating
- Recommendations to developers or users

Write your analysis in plain English, no JSON.

Permissions:
{chunk_text}
"""
    return call_groq_llm(prompt)

# === STEP 5: Generate Executive Summary from All Results ===
def generate_summary(results):
    combined_text = "\n\n---\n\n".join(results)
    summary_prompt = f"""You are an Android security consultant. Based on this analysis, give a plain-text executive summary.

Analysis:
{combined_text}

Write 3 bullet points summarizing the overall security risks, user impact, and developer recommendations.
Avoid using technical terms or JSON.
"""
    return call_groq_llm(summary_prompt)

# === MAIN ===
def main():
    print("\n🔍 Starting permission analysis...")

    permissions = extract_permissions(MOBSF_REPORT_PATH)
    if not permissions:
        return

    chunks = chunk_permissions(permissions)
    results = []

    print(f"🧠 Analyzing {len(chunks)} permission chunk(s)...\n")
    for i, chunk in enumerate(chunks, 1):
        print(f"⏳ Analyzing chunk {i}/{len(chunks)}...")
        result = analyze_permission_chunk(chunk)
        if result:
            results.append(result)
        time.sleep(1)

    print("\n🧾 Generating final executive summary...\n")
    summary = generate_summary(results)

    print("\n📋 Executive Summary:")
    print(summary or "No summary available.")

if __name__ == "__main__":
    main()
