import os
from pathlib import Path
from dotenv import load_dotenv
from groq import Groq
from openai import OpenAI
from database import get_recent_logs

# Load .env file
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

def get_ai_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is missing.")
    # Routes OpenAI SDK directly to Groq's high-speed API
    return OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=api_key,
    )

def ask_hids_agent(user_query: str) -> str:
    client = get_ai_client()
    recent_events = get_recent_logs(limit=20)

    if not recent_events:
        log_context = "No security alerts have been recorded in the database yet."
    else:
        context_lines = []
        for ts, src, attack, sev, raw, ip in recent_events:
            context_lines.append(f"[{ts}] Severity:{sev} | Threat:{attack} | Source IP:{ip} | Log:{raw}")
        log_context = "\n".join(context_lines)

    system_prompt = f"""
You are an elite Tier-3 SOC Analyst assistant embedded in a Host-Based Intrusion Detection System (HIDS).
Analyze the recorded log alerts provided below and answer the analyst's questions.

Ground Truth Security Logs (Most recent first):
--------------------------------------------------
{log_context}
--------------------------------------------------

Instructions:
1. Ground your answers strictly in the provided log data.
2. Summarize attack patterns, target users, attacker IPs, and threat counts.
3. Provide concrete threat assessment and actionable remediation advice.
4. Be concise and professional.
"""

    # Use the active model identified from Step 1
    response = client.chat.completions.create(
        model="allam-2-7b",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query}
        ],
        temperature=0.2
    )
    return response.choices[0].message.content




