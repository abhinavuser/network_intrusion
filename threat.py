import requests

THREAT_API_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY = "1234567890abcdef1234567890abcdef" #dummy

def check_ip_threat(ip):
    headers = {"Key": API_KEY, "Accept": "application/json"}
    response = requests.get(f"{THREAT_API_URL}?ipAddress={ip}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["abuseConfidenceScore"]
    return None

ip_to_check = "192.168.1.1"
threat_score = check_ip_threat(ip_to_check)
print(f"Threat Score for {ip_to_check}: {threat_score}")
threat_score = check_ip_threat(features['src_ip'])
print(f"Packet from {features['src_ip']} has Threat Score: {threat_score}")
