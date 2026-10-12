
from collections import Counter

LOG_FILE = "sample_logs.txt"
ALERT_THRESHOLD = 5


def analyze_logs():
    failed_attempts = Counter()

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                parts = line.split()

                if len(parts) != 3:
                    print(f"Skipping invalid line {line_number}")
                    continue

                timestamp, ip_address, status = parts

                if status == "FAILED":
                    failed_attempts[ip_address] += 1

    except FileNotFoundError:
        print(f"Error: {LOG_FILE} was not found.")
        return

    print("SECURITY LOG ANALYSIS")
    print("---------------------")

    if not failed_attempts:
        print("No failed login attempts found.")
        return

    for ip_address, count in failed_attempts.most_common():
        print(f"{ip_address}: {count} failed login(s)")

        if count >= ALERT_THRESHOLD:
            print("  ALERT: Repeated failures — review this address.")


if __name__ == "__main__":
    analyze_logs()
