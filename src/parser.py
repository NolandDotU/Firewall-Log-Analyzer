def parse_firewall_logs(log_file):
    logs = []

    with open(log_file, "r") as f:
        for line in f:
            parts = line.strip().split()

            log = {
                "timestamp": f"{parts[0]} {parts[1]}",
                "action": parts[2],
                "protocol": parts[3],
                "source_ip": parts[4],
                "destination_ip": parts[5],
                "port": parts[6]
            }

            logs.append(log)

    return logs


if __name__ == "__main__":
    data = parse_firewall_logs("../logs/firewall.log")
    for entry in data:
        print(entry)