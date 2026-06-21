#!/usr/bin/env python3
"""
=============================================================
Wazuh → MISP Reverse Feed Integration
=============================================================
Function: When Wazuh detects an attack, automatically push IOC
          (IP, signature, category) to MISP as a new event
          or add attributes to an existing event.

Trigger : Called via Wazuh custom integration

Setup   :
  1. Put the file in directory /var/ossec/integrations/
  2. chmod +x custom-misp-push
  3. chmod +x custom-misp-push.py
  4. add integration config to ossec.conf (lihat bagian bawah)

Configuration in ossec.conf:
  <integration>
    <name>custom-misp-push</name>
    <hook_url>https://YOUR_MISP_IP</hook_url>
    <api_key>YOUR_MISP_API_KEY</api_key>
    <alert_format>json</alert_format>
    <level>10</level>
  </integration>
=============================================================
"""

import sys
import os
import json
import requests
import ipaddress
from datetime import datetime, timezone
from requests.exceptions import ConnectionError, Timeout

# ─── Konfigurasi ────────────────────────────────────────────

# read from arguments (format Wazuh integration):
#   argv[1] = path to alert JSON
#   argv[2] = api_key from ossec.conf <api_key>
#   argv[3] = hook_url from ossec.conf <hook_url>

alert_file_path = sys.argv[1]
MISP_API_KEY    = sys.argv[2]
MISP_BASE_URL   = sys.argv[3].rstrip('/')
ALLOW_PRIVATE_IP = True

# Change with path CA cert MISP if MISP uses self-signed cert.
# Example: MISP_VERIFY_SSL = "/etc/ssl/certs/misp-ca.pem"
MISP_VERIFY_SSL = False # TODO: change to CA cert path in production

MISP_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
}

# Log file for debugging
LOG_FILE = "/var/ossec/logs/misp-push.log"

# ─── Rule ID that will be push to MISP ──────────────────────
# Only attack with this rule ID will be sent to MISP
# Customize with rule ID in your environment

PUSH_RULE_IDS = {
    # SQLi
    "100130", "100131", "100132", "100133", "100134", "100135",
    # RCE PostgreSQL
    "100136", "100137", "100138", "100139", "100140",
    # ModSecurity attacks
    "100302", "100305", "100306", "100307", "100308", "100309", "100310",
    # Suricata high severity
    "100201", "100206", "100209", "100210", "100212",
    # Brute force
    "100105", "100106", "5712",
    # Correlation rules (paling penting)
    "100500", "100501", "100505", "100506", "100507",
    "100510", "100511", "100512", "100513", "100514", "100515",
    # MISP IoC confirmed
    "100622", "100623",
}

# ─── Mapping rule group → MISP threat category ───────────────
GROUP_TO_CATEGORY = {
    # Reconnaissance / scanning -> attacker is mapping the target
    "reconnaissance":          "Targeting data",
    "scanner":                 "Targeting data",
    "nmap":                    "Targeting data",
    "recon":                   "Targeting data",
 
    # Exploit delivery / injection / web attacks -> the attack payload itself
    "sqli":                    "Payload delivery",
    "blind_sqli":              "Payload delivery",
    "rce":                     "Payload delivery",
    "xss":                     "Payload delivery",
    "lfi":                     "Payload delivery",
    "rfi":                     "Payload delivery",
    "attack":                  "Payload delivery",
    "payload_download":        "Payload delivery",
    "command_execution":       "Payload delivery",
    "file_write":              "Payload delivery",
    "function_abuse":          "Payload delivery",
 
    # Dropped artifacts on disk / DB as a result of the attack
    "data_destruction":        "Artifacts dropped",
    "file_read":               "Artifacts dropped",
 
    # Maintaining access / surviving reboot / config changes for persistence
    "config_manipulation":     "Persistence mechanism",
    "account_creation":        "Persistence mechanism",
    "account_manipulation":    "Persistence mechanism",
 
    # Network-level behavior: auth, C2, brute force, lateral comms
    "bruteforce":              "Network activity",
    "authentication_failed":   "Network activity",
    "authentication_failures": "Network activity",
    "authentication_success":  "Network activity",
    "data_exfiltration":       "Network activity",
    "c2":                      "Network activity",
    "reverse_shell":           "Network activity",
    "data_access":             "Network activity",
    "dml":                     "Network activity",
    "ddl":                     "Network activity",
 
    # Confirmed multi-stage activity / campaigns -> contextual, not a single IOC type
    "attack_chain":            "Other",
    "kill_chain":              "Other",
    "attack_campaign":         "Other",
    "automated_attack":        "Other",
    "high_severity":           "Other",
    "not_blocked":             "Other",
    "medium_severity":         "Other",
    "low_severity":            "Other",
 
    # Confirmed via MISP threat intel itself -> internal correlation reference
    "confirmed_breach":        "Internal reference",
    "misp_alert":              "Internal reference"
}

# ─── Helper Functions ────────────────────────────────────────

def log(msg: str):
    """Write log to file and stdout."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{timestamp}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_pushable_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        # Selalu skip loopback dan link-local
        if obj.is_loopback or obj.is_link_local or obj.is_unspecified:
            return False
        # Jika mode internal aktif, izinkan IP private
        if ALLOW_PRIVATE_IP:
            return True
        return not obj.is_private
    except ValueError:
        return False

#def is_public_ip(ip: str) -> bool:
#    """Return True if IP is global/public (not private/loopback)."""
#    try:
#        return ipaddress.ip_address(ip).is_global
#    except ValueError:
#        return False


def get_misp_category(alert: dict) -> str:
    """Determine MISP category based on rule groups from alert."""
    groups = alert.get("rule", {}).get("groups", [])
    for group in groups:
        if group in GROUP_TO_CATEGORY:
            return GROUP_TO_CATEGORY[group]
    return "Intrusion Attempt"  # default


def extract_ioc(alert: dict) -> dict | None:
    """
    Extract IOC from Wazuh alert.
    Return dict containing IP, description, and metadata,
    or None if no IoC can be extracted.
    """
    # Try to extract source IP from various fields
    src_ip = (
        alert.get("data", {}).get("srcip") or
        alert.get("data", {}).get("src_ip") or
        alert.get("data", {}).get("transaction", {}).get("client_ip")
    )

    if not src_ip or not is_pushable_ip(src_ip):
        log(f"SKIP: No public IP found in alert rule_id={alert.get('rule', {}).get('id')}")
        return None

    rule        = alert.get("rule", {})
    agent       = alert.get("agent", {})
    description = rule.get("description", "Wazuh Detection")
    rule_id     = rule.get("id", "unknown")
    rule_level  = rule.get("level", 0)
    groups      = rule.get("groups", [])
    agent_name  = agent.get("name", "unknown")
    agent_ip    = agent.get("ip", "unknown")
    timestamp   = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

    return {
        "ip":          src_ip,
        "description": description,
        "rule_id":     rule_id,
        "rule_level":  rule_level,
        "groups":      groups,
        "agent_name":  agent_name,
        "agent_ip":    agent_ip,
        "timestamp":   timestamp,
    }


def create_misp_event(ioc: dict) -> str | None:
    """
    Create new MISP event and return event_id.
    Event created with info from Wazuh alert.
    """
    category   = get_misp_category({"rule": {"groups": ioc["groups"]}})
    event_info = (
        f"[Wazuh] {ioc['description']} | "
        f"Rule: {ioc['rule_id']} | "
        f"Agent: {ioc['agent_name']} ({ioc['agent_ip']})"
    )

    payload = {
        "Event": {
            "info":             event_info,
            "threat_level_id":  "1" if ioc["rule_level"] >= 13 else
                                 "2" if ioc["rule_level"] >= 10 else "3",
            "analysis":         "0",    # Initial
            "distribution":     "0",    # Your organisation only
            "date":             datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "published":        False,
            "Attribute": [
                {
                    "type":     "ip-src",
                    "category": category,
                    "value":    ioc["ip"],
                    "comment":  (
                        f"Detected by Wazuh Rule {ioc['rule_id']} - "
                        f"{ioc['description']} at {ioc['timestamp']}"
                    ),
                    "to_ids":   True,
                }
            ],
            "Tag": [
                {"name": "wazuh:automated"},
                {"name": f"wazuh:rule-{ioc['rule_id']}"},
                {"name": f"wazuh:agent-{ioc['agent_name']}"},
            ],
        }
    }

    try:
        resp = requests.post(
            f"{MISP_BASE_URL}/events",
            headers=MISP_HEADERS,
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        event_id = resp.json().get("Event", {}).get("id")
        log(f"MISP EVENT CREATED: event_id={event_id} ip={ioc['ip']} rule={ioc['rule_id']}")
        return event_id
    except (ConnectionError, Timeout) as e:
        log(f"ERROR: Cannot connect to MISP - {e}")
        return None
    except Exception as e:
        log(f"ERROR: Failed to create MISP event - {e}")
        return None


def search_existing_event(ip: str) -> str | None:
    """
    Search if the IP already exists as an attribute in MISP.
    Return event_id if found, None if not.
    Avoid duplicate events for the same IP.
    """
    try:
        resp = requests.get(
            f"{MISP_BASE_URL}/attributes/restSearch/value:{ip}",
            headers=MISP_HEADERS,
            verify=MISP_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        attributes = data.get("response", {}).get("Attribute", [])
        if attributes:
            return attributes[0].get("event_id")
    except Exception as e:
        log(f"WARN: Failed to search existing MISP event for {ip} - {e}")
    return None


def add_attribute_to_event(event_id: str, ioc: dict):
    """
    Add new attribute to existing MISP event.
    Used to avoid duplicate events for the same IP.
    """
    category = get_misp_category({"rule": {"groups": ioc["groups"]}})
    payload = {
        "type":     "text",
        "category": "External analysis",
        "value": (
            f"[Wazuh] Rule {ioc['rule_id']}: {ioc['description']} "
            f"at {ioc['timestamp']} from agent {ioc['agent_name']} ({ioc['agent_ip']})"
        ),
        "comment":  f"Additional detection for {ioc['ip']}",
        "to_ids":   False,
    }
    try:
        resp = requests.post(
            f"{MISP_BASE_URL}/attributes/add/{event_id}",
            headers=MISP_HEADERS,
            json=payload,
            verify=MISP_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        log(f"MISP ATTRIBUTE ADDED: event_id={event_id} rule={ioc['rule_id']} ip={ioc['ip']}")
    except Exception as e:
        log(f"ERROR: Failed to add attribute to event {event_id} - {e}")


# ─── Main ────────────────────────────────────────────────────

def main():
    # 1. Read alert from file
    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except Exception as e:
        log(f"ERROR: Cannot read alert file {alert_file_path} - {e}")
        sys.exit(1)

    # 2. Check if the rule ID needs to be pushed
    rule_id = str(alert.get("rule", {}).get("id", ""))
    if rule_id not in PUSH_RULE_IDS:
        log(f"SKIP: Rule {rule_id} not in push list")
        sys.exit(0)

    # 3. Extract IoC
    ioc = extract_ioc(alert)
    if not ioc:
        sys.exit(0)

    log(f"PROCESSING: rule_id={rule_id} level={ioc['rule_level']} ip={ioc['ip']}")

    # 4. Check if the IP already exists in MISP (avoid duplicates)
    existing_event_id = search_existing_event(ioc["ip"])

    if existing_event_id:
        # IP already known to MISP → add new context to existing event
        log(f"IP {ioc['ip']} already in MISP event {existing_event_id}, adding attribute...")
        add_attribute_to_event(existing_event_id, ioc)
    else:
        # New IP → create new event
        log(f"IP {ioc['ip']} is new to MISP, creating event...")
        create_misp_event(ioc)


if __name__ == "__main__":
    main()
