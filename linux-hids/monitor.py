#!/usr/bin/env python3

"""
=========================================================
 Endpoint Detection (journalctl + auditd + UFW)
 PRINT-ONLY MODE (no blocking / no external alerts yet)
=========================================================

Detections covered:
1–4  : Command execution (via auditd execve)
6,7  : SSH brute force / invalid user (journalctl)
16   : Cron activity (journalctl)
19   : SSH key access (~/.ssh/authorized_keys) (auditd)
20   : useradd/usermod/userdel (journalctl)
21   : sudo usage (journalctl)
23   : sudoers modification (journalctl + auditd hint)
24   : root command exec (journalctl)
25   : access to /root (auditd hint)
26   : log clearing (journalctl)
31   : /etc/shadow access (auditd)
34   : suspicious script execution (auditd patterns)
36   : local scanning via UFW logs

Run:
    sudo python3 monitor.py
"""

import subprocess
import re
from datetime import datetime, timedelta
from collections import defaultdict
import requests
import json
#import socket
#import threading

# =========================
# CONFIG
# =========================

#JOURNAL_CMD = ["journalctl", "-f", "-n", "0"]
JOURNAL_CMD = ["journalctl", "-f", "-n", "0", "-o", "cat", "--no-pager"]
AUDIT_CMD   = ["tail", "-F", "/var/log/audit/audit.log"]
FAIL2BAN_CMD = ["tail", "-F", "/var/log/fail2ban.log"]

#LOGSTASH_ENABLED = True
#LOGSTASH_HOST = "127.0.0.1"
#LOGSTASH_PORT = 5000

FAILED_THRESHOLD = 5
failed_attempts = defaultdict(list)
FAILED_WINDOW = 60  # seconds

SUSPICIOUS_PATTERNS = [
    r"bash\s+-i",
    r"/dev/tcp/",
    r"nc\s",
    r"netcat",
    r"curl\s+.*\|\s*bash",
    r"wget\s+.*\|\s*bash",
    r"python\s+-c",
    r"perl\s+-e",
    r"base64\s+-d"
]

correlation_state = {}
TIME_WINDOW = 120  # seconds

# ================= ALERT CONFIG =================

TELEGRAM_ENABLED = True
TELEGRAM_TOKEN = <YOUR_TOKEN>	#redacted my token for privacy reasons
CHAT_ID = <YOUR_CHAT_ID>	#redacted my chat ID for privacy reasons

# =========================
# HELPERS
# =========================

def ts():
    return datetime.utcnow().isoformat()

def build_event(title, src, mitre, details, severity="MEDIUM", ip=None):
    return {
        "timestamp": ts(),
        "event": title,
        "source": src,
        "mitre": mitre,
        "severity": severity,
        "ip": ip,
        "details": details
    }

def alert(title, src, mitre, details, severity="MEDIUM", ip=None):
    event = build_event(title, src, mitre, details, severity, ip)

    # Pretty print (unchanged feel)
    #print("\n" + "="*72)
    #print(f"[{event['timestamp']}] 🚨 {event['event']}")
    #print(f"Source : {event['source']}")
    #print(f"MITRE  : {event['mitre']}")
    #print(f"Severity: {event['severity']}")
    #print(f"Detail : {event['details']}")
    #print("="*72)

    # JSON output (NEW 🔥)
    print("\n" + "="*72)
    print("JSON:", json.dumps(event))
    print("\n" + "="*72)
    
    send_telegram(json.dumps(event, indent=2))
    #send_to_logstash(event)
#    threading.Thread(target=send_telegram, args=(json.dumps(event, indent=2),), daemon=True).start()
#    threading.Thread(target=send_to_logstash, args=(event,), daemon=True).start()
    print("DEBUG: Alert processed")

def extract_ip(line):
    # Match IPv4 OR IPv6 after "from"
    m = re.search(r'from ([0-9a-fA-F:\.]+)', line)
    if m:
        return m.group(1)

    # Fallback for cases like rhost=::1
    m = re.search(r'rhost=([0-9a-fA-F:\.]+)', line)
    if m:
        return m.group(1)

    return None

#def spawn(cmd):
#    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def spawn(cmd):
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1   # 🔥 line buffered
    )

def send_telegram(msg):
    if not TELEGRAM_ENABLED:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": CHAT_ID, "text": msg})
    except Exception as e:
        print("Telegram error:", e)

#def send_to_logstash(event):
#    if not LOGSTASH_ENABLED:
#        return
#    try:
#        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#        sock.sendto((json.dumps(event) + "\n").encode(),
#                    (LOGSTASH_HOST, LOGSTASH_PORT))
#    except Exception as e:
#        print("Logstash UDP error:", e)
        
def track_event(ip, event_type):
    now = datetime.utcnow()

    if ip not in correlation_state:
        correlation_state[ip] = []

    correlation_state[ip].append((event_type, now))

    # Remove old events
    correlation_state[ip] = [
        (e, t) for e, t in correlation_state[ip]
        if (now - t).seconds < TIME_WINDOW
    ]

def check_bruteforce_success(ip):
    events = correlation_state.get(ip, [])

    has_bruteforce = False

    for event, t in events:
        if event == "bruteforce":
            has_bruteforce = True

        if event == "login_success" and has_bruteforce:
            alert(
                "Brute Force → Login Success (Account Compromise)",
                "correlation",
                "T1110 → T1078",
                f"{ip} brute force followed by successful login",
                "CRITICAL",
                ip
            )

            # prevent duplicate alerts
            correlation_state[ip] = []
            return

# =========================
# DETECTIONS — JOURNALCTL
# =========================

def handle_journal_line(line):
    l = line.strip()
    print("JOURNAL:", l)

    # ================= SSH FAILED PASSWORD =================
    if "Failed password" in l:
        ip = extract_ip(l)

        if ip:
            now = datetime.utcnow()

            # Add current attempt
            failed_attempts[ip].append(now)

            # Remove old attempts outside window
            failed_attempts[ip] = [
                t for t in failed_attempts[ip]
                if (now - t).total_seconds() < FAILED_WINDOW
            ]

            # Debug
            print(f"DEBUG: {ip} attempts in window:", len(failed_attempts[ip]))

            # Trigger if threshold reached
            if len(failed_attempts[ip]) >= FAILED_THRESHOLD:
                alert(
                    "SSH Brute Force Detected",
                    "journalctl",
                    "T1110",
                    f"{ip} → {len(failed_attempts[ip])} attempts in {FAILED_WINDOW}s",
                    "HIGH",
                    ip
                )

                # Reset AFTER alert to avoid spam
                failed_attempts[ip] = []

                track_event(ip, "bruteforce")

    # ================= INVALID USER =================
    if "Invalid user" in l:
        alert("Invalid User Login Attempt", "journalctl", "T1110", l, "MEDIUM")

    # ================= USER MGMT =================
    if any(k in l for k in ["useradd", "usermod", "userdel", "new user"]):
        alert("User Account Modification", "journalctl", "T1136", l, "HIGH")

    # ================= SUDOERS =================
    if "sudoers" in l or "visudo" in l:
        alert("Sudoers Modification", "journalctl", "T1548", l, "HIGH")

    # ================= LOG CLEARING =================
    if "journalctl" in l and ("vacuum" in l or "--vacuum" in l):
        alert("Log Clearing Detected", "journalctl", "T1070", l, "HIGH")

    # ================= SSH SUCCESS =================
    if "Accepted password" in l or "Accepted publickey" in l:
        ip = extract_ip(l)
        if ip:
            alert("SSH Login Success", "journalctl", "T1078", l, "MEDIUM", ip)

            track_event(ip, "login_success")
            check_bruteforce_success(ip)

# =========================
# FAIL2BAN
# =========================

def handle_fail2ban(line):
    if "Ban" in line:
        alert("IP Banned by Fail2Ban", "fail2ban", "Response",
              line.strip(), "HIGH")

# =========================
# DETECTIONS — AUDITD
# =========================

def parse_audit_kv(line):
    kv = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            kv[k] = v.strip('"')
    return kv

def handle_audit_line(line):
    l = line.strip()

    if "type=EXECVE" not in l and "type=SYSCALL" not in l:
        return

    kv = parse_audit_kv(l)
    comm = kv.get("comm", "")
    args = " ".join([kv.get(k, "") for k in sorted(kv) if k.startswith("a")])
    full_cmd = f"{comm} {args}".strip()

    if comm and re.search(r"(uname|ifconfig|ip\s|ps\s|dpkg|rpm)", full_cmd):
        alert("Recon Command Execution", "auditd", "TA0043",
              full_cmd, "LOW")

    if ".ssh/authorized_keys" in l:
        alert("SSH Key File Access", "auditd", "T1098",
              "Access to ~/.ssh/authorized_keys", "HIGH")

    if "/etc/shadow" in l:
        alert("Sensitive File Access", "auditd", "T1003",
              full_cmd or l, "HIGH")

    if "/root" in l:
        alert("Access to /root Directory", "auditd", "T1087",
              full_cmd or l, "MEDIUM")

    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, full_cmd):
            alert("Suspicious Command Execution", "auditd", "T1059",
                  full_cmd, "HIGH")
            break

# =========================
# MAIN LOOP
# =========================

def monitor():
    print("🚀 Monitoring with JSON output + Fail2Ban integration...\n")

    p_j = spawn(JOURNAL_CMD)
    p_a = spawn(AUDIT_CMD)
    p_f = spawn(FAIL2BAN_CMD)

    while True:
        if p_j.stdout.readable():
            line = p_j.stdout.readline()
            if line:
                handle_journal_line(line)

        if p_a.stdout.readable():
            line = p_a.stdout.readline()
            if line:
                handle_audit_line(line)

        if p_f.stdout.readable():
            line = p_f.stdout.readline()
            if line:
                handle_fail2ban(line)

# =========================
# ENTRY
# =========================

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n🛑 Stopped")
