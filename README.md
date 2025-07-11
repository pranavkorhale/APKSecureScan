# 🔐 APKSecureScan – LLM-Powered Android APK Security Analyzer

APKSecureScan is an AI-assisted static analysis tool that scans Android APK files for excessive permissions, sensitive API usage, and potential security risks. By combining the strengths of **MobSF**, **SuSi**, and **Groq LLM**, it generates executive summaries to support both **technical audits** and **cybersecurity education**.

---

## 🚀 Features

- 📦 **Static Analysis of APKs** using MobSF
- 🔍 **Sensitive API Detection** via SuSi integration
- 🤖 **LLM-based Risk Summarization** powered by Groq's LLaMA-3
- 🖥️ **Streamlit UI** for user-friendly interaction
- 🔐 **Environment-based Secrets Management**

---

## 🎯 Use Case

This tool is ideal for:
- **Cybersecurity Analysts** auditing mobile apps
- **Educators/Students** learning Android security concepts

---

## 🛠️ Tech Stack

| Layer          | Tool/Service               |
| -------------- | -------------------------- |
| 🧠 LLM         | [Groq API](https://groq.com/) (LLaMA 3) |
| 🔬 Static Scan | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) |
| 🔎 API Mapper  | [SuSi (IccTA)](https://github.com/secure-software-engineering/SuSi) |
| 💻 Frontend    | Streamlit                  |
| 🔐 Secrets     | dotenv + `.env`            |

---

## 📦 Installation

> Requires: `Python 3.9+`, `pip`, and MobSF running locally (`http://localhost:8000`)

```bash
# Clone the repo
git clone https://github.com/pranavkorhale/APKSecureScan.git
cd APKSecureScan

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
