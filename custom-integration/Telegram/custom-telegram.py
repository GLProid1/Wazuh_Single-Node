#!/usr/bin/env python3
import sys
import json
import requests
import html
import os

# --- Helper function to read file .env ---
def load_env(env_path):
    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_DATA = load_env(os.path.join(CURRENT_DIR, '.env'))

CHAT_ID = int(ENV_DATA.get('CHAT_ID'))
TELEGRAM_API = ENV_DATA.get('TELEGRAM_API')
hook_url = f"https://api.telegram.org/bot{TELEGRAM_API}/sendMessage"

def create_message(alert_json):
    # Get alert information, use empty string if field didn't exist
    title = alert_json['rule']['description'] if 'description' in alert_json['rule'] else ''
    description = alert_json['full_log'] if 'full_log' in alert_json else ''
    description = description.replace("\\n", "\n")
    MAX_DESC_LENGTH = 300
    if len(description) > MAX_DESC_LENGTH:
      description = description[:MAX_DESC_LENGTH] + "... (truncated)"
    alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else ''
    group_array = ', '.join(alert_json['rule']['groups']) if 'groups' in alert_json['rule'] else ''
    groups = group_array.replace("_", " ")
    rule_id = alert_json['rule']['id'] if 'rule' in alert_json else ''
    agent_name = alert_json['agent']['name'] if 'name' in alert_json['agent'] else ''
    agent_id = alert_json['agent']['id'] if 'id' in alert_json['agent'] else ''
    agent_ip = alert_json['agent']['ip'] if 'ip' in alert_json['agent'] else ''

    try:
        src_ip = alert_json['data']['srcip'] if 'srcip' in alert_json['data'] else ''
    except:
        src_ip = ''

    title = html.escape(str(title))
    description = html.escape(str(description))
    groups = html.escape(str(groups))
    src_ip = html.escape(str(src_ip))
    rule_id = html.escape(str(rule_id))
    alert_level = html.escape(str(alert_level))
    agent_name = html.escape(str(agent_name))
    agent_id = html.escape(str(agent_id))
    agent_ip = html.escape(str(agent_ip))

    msg_content = f'<b>{title}</b>\n\n'

    if description:
        msg_content += f'{description}\n\n'  #Langsung pakai, tanpa escape

    if groups:
        msg_content += f'<b>Groups:</b> {groups}\n'

    if src_ip:
        msg_content += f'<b>Source IP:</b> {src_ip}\n'

    msg_content += f'<b>Rule:</b> {rule_id} (Level {alert_level})\n\n'

    if agent_name:
        msg_content += f'<b>Agent Name:</b> {agent_name} ({agent_id})\n'

    if agent_ip:
        msg_content += f'<b>Agent IP:</b> {agent_ip}'

    msg_data = {
        'chat_id': CHAT_ID,
        'text': msg_content,
        'parse_mode': 'HTML'
    }

    # Debug information
    with open('/var/ossec/logs/integrations.log', 'a') as f:
        f.write(f'MSG: {msg_data}\n')

    return json.dumps(msg_data)

alert_file = open(sys.argv[1])

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Send the request
msg_data = create_message(alert_json)
headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
response = requests.post(hook_url, headers=headers, data=msg_data)
print("telegram : ", msg_data)

# Debug information
with open('/var/ossec/logs/integrations.log', 'a') as f:
    f.write(f'telegram response: {response.status_code} - {response.text}\n')

sys.exit(0)
