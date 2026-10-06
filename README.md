# Project Documentation: Host-Based Intrusion Detection System (HBID) + AI Log Chatbox

## 1. Project Overview
This project implements an automated Host-Based Intrusion Detection System (HIDS) combined with a Security Operations Center (SOC) AI Copilot.
The system continuously monitors local host security logs (/var/log/auth.log), extracts critical authentication threats using regular expression rule sets, persists structured telemetry into an SQLite database, and presents actionable data on an interactive Streamlit dashboard. An embedded AI Copilot powered by the Groq API (llama-3.1-8b-instant) provides instant threat analysis, attacker attribution, and copy-paste remediation commands.

## 2. System Architecture
+-------------------------------------------------------------------------+
|                        HBID DATA PIPELINE FLOW                          |
|                                                                         |
|  [ Linux Auth Stream ]           [ Detection Daemon ]                   |
|  /var/log/auth.log     ======>   watcher.py (Regex Matching)            |
|                                         ||                              |
|                                         || (Inserts Alert Rows)         |
|                                         \/                              |
|                              [ Relational Database ]                    |
|                              hids_events.db (SQLite)                    |
|                                      //    \\                           |
|       (Reads Recent Logs)           //      \\   (Displays Metrics)     |
|                                    //        \\                         |
|                                    \/        \/                         |
|         [ Groq AI Agent ]                        [ SOC UI Console ]     |
|         ai_agent.py (LLaMA-3.1) <=============>  app.py (Streamlit)     |
|                               (Chat Prompts)                            |
+-------------------------------------------------------------------------+

## 3. Directory and File Structure
task1_HIDS/
├── .env                  # API keys and environment secrets (not tracked in Git)
├── .gitignore            # Excludes venv, databases, and cache folders
├── ai_agent.py           # Groq API integration and prompt engineering logic
├── app.py                # Streamlit SOC dashboard user interface
├── database.py           # SQLite connection setup, schema, and query functions
├── requirements.txt      # Python dependencies list
├── watcher.py            # Real-time log monitoring and detection engine
└── README.md             # Project documentation and setup guide

## 4. Key Component Breakdown
    • watcher.py (Ingestion & Detection Engine):
A background daemon that monitors /var/log/auth.log for new entries. It checks each line against security regex patterns to detect failed SSH logins, brute-force patterns, and unauthorized privilege escalation (sudo failures).
    • database.py (Storage Layer):
Initializes hids_events.db and provides functions to insert security alerts and fetch recent records for the dashboard and the AI agent.
    • ai_agent.py (Groq AI Security Copilot):
Connects to Groq using the llama-3.1-8b-instant model. It retrieves the latest 20 security alerts from SQLite, injects them into an analyst prompt, and produces clear, actionable SOC triage summaries.
    • app.py (Interactive Dashboard):
A web dashboard built with Streamlit featuring real-time event counters, high-severity warning badges, filterable log tables, and an interactive chat interface for the AI Copilot.

## 5. Database Schema
The SQLite database (hids_events.db) stores detected threats in a structured alerts table:
Column Name	 Type 	Description
id	 INTEGER PRIMARY KEY 	Unique auto-incrementing alert ID
timestamp	 TEXT 	ISO-8601 formatted event timestamp
source 	TEXT 	Generating system service (sshd, sudo)
attack_type	TEXT 	Categorized threat (SSH_BRUTE_FORCE, FAILED_SUDO)
severity 	TEXT	Severity ranking (LOW, MEDIUM, HIGH, CRITICAL)
raw_log 	TEXT 	Exact raw log message recorded by Linux
ip_address 	TEXT	Source IPv4 address of the attacker

## 6.0 Prerequisites and Environment Setup
### 6.1 System Requirements
    • Linux OS (Kali Linux, Ubuntu, or Debian)
    • Python 3.10+
    • OpenSSH Server installed and active
    • THC-Hydra (for security testing and attack simulation)
### 6.2 Step-by-Step Installation
       1. Navigate to the project root directory:
       cd /home/kali/Documents/PROSTACKHUB_PROJECTS/task1_HBID_AIchatbot
       2. Create and activate a Python virtual environment:
python3 -m venv venv
source venv/bin/activate
       3. Install required packages:
pip install -r requirements.txt
Required packages include streamlit, groq, python-dotenv, and watchdog).
       4. Configure the API Key:
Create or edit the .env file in the root folder:
nano .env
Add your key without quotes or spaces:
GROQ_API_KEY=gsk_yourActualGroqAPIKeyHere
Save and close (Ctrl + O, Enter, Ctrl + X).

## 7. Execution and Operation Guide
Run the system using two separate terminal windows:

### Terminal 1: Launch the Detection Engine
The log watcher requires root privileges to read protected system log streams:
cd /home/kali/Documents/PROSTACKHUB_PROJECTS/task1_HIDS_AIchatbot
source venv/bin/activate
sudo ./venv/bin/python3 watcher.py

Verification: The terminal prints [+] Monitoring /var/log/auth.log for security events...

### Terminal 2: Launch the Streamlit Dashboard
cd /home/kali/Documents/PROSTACKHUB_PROJECTS/task1_HIDS_AIchatbot
source venv/bin/activate
streamlit run app.py

## 8. Attack Simulation and Verification
### 8.1 SSH Brute-Force Attack (Hydra)
Open a third terminal window to simulate a brute-force attack:
    • Create a temporary wordlist
printf "password123\nadmin\nletmein\n123456\n" > /tmp/wordlist.txt
    • Run Hydra against the local SSH service
hydra -l testuser -P /tmp/wordlist.txt ssh://127.0.0.1:22
Expected Result:
    • Terminal 1 (watcher.py) flags repeated failed password attempts from 127.0.0.1.
    • The events are stored in hids_events.db.
    • Click Refresh Telemetry on the dashboard to view the new rows.

### 8.2 Privilege Escalation Check
Simulate unauthorized sudo attempts:
sudo -k && sudo whoami
(Enter an intentionally wrong password when prompted).
Expected Result:
watcher.py records a FAILED_SUDO event with MEDIUM severity.

### 8.3 Querying the AI Copilot
In the Streamlit chat box, ask:
    • "What happened in the last hour? Are there any critical threats?"
    • "Which IP addresses are attacking the server, and what firewall commands should I 	use to block them?"
The AI analyst reads the SQLite database context and replies with attack details and firewall rules (such as sudo ufw deny from 127.0.0.1).

## 9. Troubleshooting Common Issues
    • GROQ_API_KEY environment variable is missing:
Ensure there are no spaces or quotes around the = sign in .env. The line must strictly read GROQ_API_KEY=gsk_.…
    • ModuleNotFoundError: No module named groq:
Deactivate Anaconda (conda deactivate) and ensure you are using the virtual environment interpreter (source venv/bin/activate).
    • Error 404: Model not found:
Ensure ai_agent.py is set to an active model name such as llama-3.1-8b-instant.