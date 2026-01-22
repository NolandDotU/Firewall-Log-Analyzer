from parser import parse_firewall_logs
from analyzer import detect_suspicious_ips


def generate_report():
    logs = parse_firewall_logs("../logs/firewall.log")
    suspicious_ips = detect_suspicious_ips(logs)

    with open("../reports/firewall_report.md", "w") as report:
        report.write("# Firewall Log Analysis Report\n\n")
        report.write(f"Total log entries analyzed: {len(logs)}\n\n")

        if suspicious_ips:
            report.write("## Susupiciouse IP Addresses\n")
            for ip, count in suspicious_ips.items():
                report.write(f"- {ip}: {count} denied attempts\n")

            report.write("\n## Recommendations\n")
            report.write("- Block suspiciouse IPs at firewall level\n")
            report.write("- Enable rate limiting on SSH and critical services\n")
            report.write("- Monitor denied traffi trends daily\n")
        else:
            report.write("No suspicious activity detected.\n")

if __name__ == "__main__":
    generate_report()
    