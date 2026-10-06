import streamlit as st
import sqlite3
import pandas as pd
from ai_agent import ask_hids_agent
from database import init_db

init_db()

st.set_page_config(page_title="HIDS + AI Log Chatbot", page_icon="🛡️", layout="wide")
st.title("🛡️ Host-Based Intrusion Detection System (HIDS) + AI Copilot")

col_left, col_right = st.columns([1.2, 1])

with col_left:
    st.subheader("📊 Live Security Event Feed")
    if st.button("Refresh Telemetry"):
        st.rerun()

    conn = sqlite3.connect("hids_events.db")
    try:
        df = pd.read_sql_query("SELECT id, timestamp, attack_type, severity, ip_address, raw_log FROM alerts ORDER BY id DESC LIMIT 50", conn)
        conn.close()
        st.dataframe(df, use_container_width=True)
    except Exception as e:
        conn.close()
        st.error(f"Database error: {e}")

with col_right:
    st.subheader("💬 SOC AI Assistant (Groq allam-2-7b)")
    st.caption("Ask questions grounded directly in your stored system telemetry.")

    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "I am your HIDS AI Copilot. Ask me about recent attacks, failed logins, or host security recommendations."}
        ]

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("e.g., What happened in the last hour?"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing log telemetry with Groq..."):
                try:
                    response_text = ask_hids_agent(prompt)
                except Exception as err:
                    response_text = f"Error communicating with AI agent: {err}"
                st.markdown(response_text)
        
        st.session_state.messages.append({"role": "assistant", "content": response_text})
