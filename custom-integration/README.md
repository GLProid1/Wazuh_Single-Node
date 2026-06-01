# 🔗 Custom Integration Documentation

All Wazuh custom integration for alert and threat intelligence.

---

## List of Integration

| Integration | Directory   | Path             | Function                                  |
| ----------- | ----------- | ---------------- | ----------------------------------------- |
| MISP Pull   | `MISP/`     | MISP → Wazuh     | Checking IOC to MISP when alert triggered |
| MISP Push   | `MISP/`     | Wazuh → MISP     | Push IOC to MISP when attack detected     |
| Telegram    | `Telegram/` | Wazuh → Telegram | Real-time notification via Telegrm Bot    |

---

## How it works

Each integration consists of **two files** with the same name:

| File             | Type                              | Function                               |
| ---------------- | --------------------------------- | -------------------------------------- |
| `custom-misp`    | Shell script (without extensions) | Entry point — called directly by wazuh |
| `custom-misp.py` | Python script                     | Main logic — called by shell wrapper   |

The shell wrapper file simply finds Wazuh's internal Python path and passes the arguments to the `.py` file. All the actual logic is in the `.py` file. The same goes for all integrations in this repo:

| Shell Wrapper      | Python Script         | Integration |
| ------------------ | --------------------- | ----------- |
| `custom-misp`      | `custom-misp.py`      | MISP Pull   |
| `custom-misp-push` | `custom-misp-push.py` | MISP Push   |
| `custom-telegram`  | `custom-telegram.py`  | Telegram    |

```
Alert Triggered
    │
    ▼
Wazuh matched <group> or <level> in <integration> configuration
    │
    ▼
Wazuh write JSON alert to a temporary file in /tmp:
→ /tmp/{integration-name}-{timestamp}-{random}.alert
    │
    ▼
Wazuh called shell wrapper with 3 arguments:
→ {shell-wrapper}  {path_alert}  {api_key}  {hook_url}
                   (argv[1])     (argv[2])  (argv[3])
    │
    ▼
The shell wrapper passes to the Python script:
→ python3 {python-script}.py  {path_alert}  {api_key}  {hook_url}
    │
    ▼
Python script reads JSON alert → proccess it → send the result to Wazuh queue
    │
    ▼
Temporary file are deleted automatically by Wazuh
```

> ⚠️ **Important — The `/tmp` Directory must exist inside the container:**
> Wazuh integratord uses `/tmp` to store temporary alerts file.
> In some Docker images, `/tmp` doesn't exist by default. Fix:
>
> ```bash
> docker exec wazuh_single-node-wazuh.manager-1 bash -c "mkdir -p /tmp"
> ```

---

## MISP Pull — `MISP/`

### Function

Every time a Wazuh alert is triggered with a certain group, the script checks whether the IP or file hash of the alert has been recorded as an IoC in MISP. If found, Wazuh creates a new alert that triggers the MISP rule (100622/100623). If not found, the IP is automatically pushed to the MISP as a new IoC.

### File

| File             | Function                                    |
| ---------------- | ------------------------------------------- |
| `custom-misp`    | Shell wrapper — entry point called by Wazuh |
| `custom-misp.py` | Python main logic                           |

### Workflow

```
Wazuh alert triggered (groups match)
    │
    ▼
custom-misp.py read JSON alert
    │
    ├── [nginx/modsecurity/web] ── extract_src_ip() → srcip / transaction.client_ip
    ├── [Windows Sysmon]        ── hash / destination IP
    ├── [Linux Sysmon]          ── destination IP / DNS query
    ├── [Syscheck]              ── MD5 / SHA256 file hash
    └── [Auth failed/syslog]    ── source IP
    │
    ▼
GET https://{MISP_IP}/attributes/restSearch/value:{ioc}
    │
    ├── [FOUND]     → send event to Wazuh queue
    │                 → trigger rule 100622 / 100623
    │                 → append IP in misp_ip_lists.txt
    │                 → SKIP push (if IP aleready exists in MISP)
    │
    └── [NOT FOUND] → push_to_misp() — create new event in MISP
                      → tag: wazuh:automated, wazuh:rule-{id}
```

### Function `extract_src_ip()`

Since different log sources store IPs in different fields, a helper function is used to extract IPs from all possible paths:

```python
def extract_src_ip(alert):
    data = alert.get("data", {})
    return (
        data.get("srcip") or                              # SSH, PostgreSQL, Syslog
        data.get("src_ip") or                             # Suricata
        data.get("client_ip") or                          # Generic
        data.get("transaction", {}).get("client_ip") or   # ModSecurity/Nginx
        data.get("win", {}).get("eventdata", {}).get("sourceIp")  # Windows
    )
```

### Konfigurasi di `ossec.conf`

```xml
<integration>
  <name>custom-misp</name>
  <group>custom_db_audit,suricata,ids,nginx,modsecurity,web,sysmon_event1,
         sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,
         sysmon_event_22,syscheck,recon,attack,web_scan,authentication_failed</group>
  <alert_format>json</alert_format>
</integration>
```

> `<hook_url>` and `<api_key>` are not used because they are configured directly in `custom-misp.py`:
>
> ```python
> misp_base_url     = "https://${MISP_IP}/attributes/restSearch/"
> misp_api_auth_key = "${AUTH_KEY}"
> ```

> ⚠️ **IMPORTANT — Matching group:**
> Wazuh uses `groups[0]` (first index) as `event_source` in the script.
> ModSecurity alerts have groups `["nginx","modsecurity","web","sqli","attack"]`
> so that `event_source = "nginx"` — make sure the `nginx` handler is present in the script
> and the `nginx` group is in the `<integration>` configuration.

### Deploy

```bash
# After file mount to local via docker-compose.yml:
# ./custom-integration/MISP/custom-misp    → /var/ossec/integrations/custom-misp
# ./custom-integration/MISP/custom-misp.py → /var/ossec/integrations/custom-misp.py

# Change the ownership of the custom file to root:wazuh
sudo chown root:999 ./custom-integration/MISP/custom-misp
sudo chown root:999 ./custom-integration/MISP/custom-misp.py

# Set permission on the HOST (not on the container, so that they are persistent after restart)
sudo chmod 750 ./custom-integration/MISP/custom-misp
sudo chmod 750 ./custom-integration/MISP/custom-misp.py

# Restart after configuration changes
docker compose restart wazuh_single-node-wazuh.manager-1
```

### Known Issues

| Issue                   | Causes                                                    | Fix                                                                                          |
| ----------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Script not called       | Group in ossec.conf does not match `groups[0]` alert      | Add groups `nginx`,`modsecurity` in `<integration>`                                          |
| IP extracted `None`     | ModSec stores IPs in `transaction.client_ip`, not `srcip` | modified `extract_src_ip()` function in `custom-misp.py`                                     |
| `verify=False`          | Self-signed cert MISP                                     | Replace it with your own CA cert path                                                        |
| Silent exit without log | Exception di-catch oleh `sys.exit()`                      | Add `integrator.debug=2` logging in `/var/ossec/etc/internal_options.conf` file in container |

---

## MISP Push — `MISP/`

### Function

When Wazuh detects a significant attack from a certain rule ID, this script automatically creates an event or adds an attribute in MISP.

### File

| File                  | Function                                    |
| --------------------- | ------------------------------------------- |
| `custom-misp-push`    | Shell wrapper — entry point called by Wazuh |
| `custom-misp-push.py` | Python main logic                           |

### Workflow

```
The alert is triggered with the rule_id in PUSH_RULE_IDS
    │
    ▼
Extract source IP via extract_src_ip()
    │
    ├── [IP loopback/link-local] → SKIP
    └── [IP valid]
          │
          ▼
          GET /attributes/restSearch/value:{ip}
          │
          ├── [IP already exist] → add attribute to existing event
          └── [New IP]      → create new MISP Event MISP:
                               · threat_level from rule level
                               · category: Network activity
                               · tags: wazuh:automated, wazuh:rule-{id}
                               · attribute type: ip-src, to_ids: true
```

### MISP Threat Level Mapping

| Wazuh Rule Level | MISP Threat Level | Label  |
| ---------------- | ----------------- | ------ |
| ≥ 13             | 1                 | High   |
| ≥ 10             | 2                 | Medium |
| < 10             | 3                 | Low    |

### Rule ID pushed to MISP

| Category        | Rule IDs                                                                               |
| --------------- | -------------------------------------------------------------------------------------- |
| SQLi PostgreSQL | 100130, 100131, 100132, 100133, 100134, 100135                                         |
| RCE PostgreSQL  | 100136, 100137, 100138, 100139, 100140                                                 |
| ModSecurity     | 100302, 100305, 100306, 100307, 100308, 100309, 100310                                 |
| Suricata High   | 100201, 100206, 100209, 100210, 100212                                                 |
| Brute Force     | 100105, 100106, 5712                                                                   |
| Correlation     | 100500, 100501, 100505, 100506, 100507, 100510, 100511, 100512, 100513, 100514, 100515 |
| MISP Confirmed  | 100622, 100623                                                                         |

### Configuration in `ossec.conf`

```xml
<integration>
  <name>custom-misp-push</name>
  <hook_url>https://YOUR_MISP_IP</hook_url>
  <api_key>YOUR_MISP_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>10</level>
</integration>
```

### Deploy

```bash
# Change the ownership of the custom file to root:wazuh
sudo chown root:999 ./custom-integration/MISP/custom-misp-push
sudo chown root:999 ./custom-integration/MISP/custom-misp-push.py

# Set permission on the HOST so that they persistent after restart
sudo chmod 750 ./custom-integration/MISP/custom-misp-push
sudo chmod 750 ./custom-integration/MISP/custom-misp-push.py

# Volume mount in docker-compose.yml:
# - ./custom-integration/MISP-push/custom-misp-push:/var/ossec/integrations/custom-misp-push
# - ./custom-integration/MISP-push/custom-misp-push.py:/var/ossec/integrations/custom-misp-push.py

# Create and set permission log file
docker exec wazuh_single-node-wazuh.manager-1 bash -c "
  touch /var/ossec/logs/misp-push.log
  chown root:wazuh /var/ossec/logs/misp-push.log
  chmod 660 /var/ossec/logs/misp-push.log
"

# Restart manager
docker compose restart wazuh_single-node-wazuh.manager-1
```

### Log File

```bash
# Monitor aktivitas push ke MISP
docker exec wazuh_single-node-wazuh.manager-1 bash -c "
  tail -f /var/ossec/logs/misp-push.log
"

# Example of normal output:
# [2026-05-22T08:34:07Z] PROCESSING: rule_id=100302 level=10 ip=192.168.141.1
# [2026-05-22T08:34:08Z] IP 192.168.141.1 is new to MISP, creating event...
# [2026-05-22T08:34:08Z] MISP EVENT CREATED: event_id=16 ip=192.168.141.1 rule=100302

# Examples of existing IPs:
# [2026-05-22T08:41:59Z] IP 192.168.141.1 already in MISP event 17, adding attribute...
# [2026-05-22T08:41:59Z] MISP ATTRIBUTE ADDED: event_id=17 rule=100302 ip=192.168.141.1
```

### Known Issues

| Issue                           | Penyebab                                            | Fix                                          |
| ------------------------------- | --------------------------------------------------- | -------------------------------------------- |
| Integration not run         | File permission `rwxrwx--x` (writable group)        | `chmod 750` on the host, not on container         |
| Empty log even though the script is running | Log file owned by `root`, not `wazuh`             | `chown :wazuh misp-push.log`            |
| IP private skipped              | `ALLOW_PRIVATE_IP = False` by default               | Set `ALLOW_PRIVATE_IP = True` for lab      |
| Event MISP without attribute      | `GROUP_TO_CATEGORY` use invalid MISP category | Change to `Network activity` (see below) |

### Valid MISP Categories

MISP only accepts certain attribute categories. If the category is invalid, the event is successfully created but the **attribute will be rejected** — the event displays the warning _"Your event has neither attributes nor objects"_.

```python
GROUP_TO_CATEGORY = {
    "sqli":                    "Network activity",
    "rce":                     "Network activity",
    "xss":                     "Network activity",
    "lfi":                     "Network activity",
    "bruteforce":              "Network activity",
    "authentication_failures": "Network activity",
    "data_exfiltration":       "Network activity",
    "data_destruction":        "Network activity",
    "malware":                 "Malware Sample",
    "c2":                      "Network activity",
    "reconnaissance":          "Network activity",
    "scanner":                 "Network activity",
    "attack_chain":            "Network activity",
    "kill_chain":              "Network activity",
    "confirmed_breach":        "Network activity",
}
```

Other valid categories: `Payload delivery`, `Artifacts dropped`, `External analysis`, `Attribution`, `Other`.

---

## Telegram — `Telegram/`

### Function

Sends real-time notification to Telegram group when Wazuh alert are triggered according to configured group and level.

### File

| File                 | Fungsi                                           |
| -------------------- | ------------------------------------------------ |
| `custom-telegram`    | Shell wrapper — entry point that called by Wazuh |
| `custom-telegram.py` | Python's main logic                               |

### Message Format

```
ModSecurity: XSS Attack Detected from 192.168.141.1

{"transaction":{"client_ip":"192.168.141.1",...}} (truncated)

Groups: nginx, modsecurity, web, xss, attack
Source IP: 192.168.141.1
Rule: 100308 (Level 10)

Agent Name: nginx (001)
Agent IP: 192.168.141.136
```

### Konfigurasi di `ossec.conf`

```xml
<integration>
  <name>custom-telegram</name>
  <hook_url>https://api.telegram.org/bot<TELEGRAM_API>/sendMessage</hook_url>
  <alert_format>json</alert_format>
  <level>5</level>
  <group>nginx,modsecurity,web,custom_db_audit,suricata,ids,threat_intel</group>
</integration>
```

### Log File

```bash
# Debug log all Telegram requests and responses
tail -f /var/ossec/logs/integrations.log
```

---

## Troubleshooting

### Integration not called at all

```bash
# Check if integratord load the integration
grep "Enabling integration" /var/ossec/logs/ossec.log | tail -5

# Check error permission
grep "write permissions\|wpopenv" /var/ossec/logs/ossec.log | tail -5
```

### Temporary alert file could no be created

```bash
# Check if /tmp file are on the container
docker exec wazuh_single-node-wazuh.manager-1 ls -la / | grep tmp

# If there is none
docker exec wazuh_single-node-wazuh.manager-1 bash -c "mkdir -p /tmp && chmod 1777 /tmp"
```

### Alert written in alerts.json file but alert not show on the Wazuh Dashboard

```bash
# Restart wazuh manager to re-sync the indexer
docker compose restart wazuh_single-node-wazuh.manager-1
```

### Check the status of all integrations at once

```bash
docker exec wazuh_single-node-wazuh.manager-1 \
  grep -i "integrat\|misp\|telegram" /var/ossec/logs/ossec.log | tail -20
```
