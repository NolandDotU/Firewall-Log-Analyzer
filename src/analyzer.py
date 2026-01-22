from parser import parse_firewall_logs
from collections import Counter


def detect_suspicious_ips(logs, threshold=3):
    denied_ips = [log["source_ip"] for log in logs if log["action"] == "DENY"]
    ip_counts = Counter(denied_ips)

    suspicious = {
        ip: count for ip, count in ip_counts.items() if count >= threshold
    }

    return suspicious


if __name__ == "__main__":
    logs = parse_firewall_logs("../logs/firewall.log")
    suspicious_ips = detect_suspicious_ips(logs)

    print("Suspicious IPs detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip} - {count} denied attempts")