import re
from collections import Counter

def detect_suspicious_activity(file_path, threshold=10):
    failed_logins = Counter()

    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Extract IP and status code
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*" .*?" (\d+)', line)
                if match:
                    ip = match.group(1)
                    status_code = match.group(2)

                    # Increment failed login count for status code 401 or failure messages
                    if status_code == '401' or 'Invalid credentials' in line:
                        failed_logins[ip] += 1

        # Filter IPs exceeding the threshold
        suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

        # Display results
        if suspicious_ips:
            print("Suspicious Activity Detected:")
            print(f"{'IP Address':<20}{'Failed Login Attempts':<10}")
            print("-" * 35)
            for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip:<20}{count:<10}")
        else:
            print("No suspicious activity detected.")

    except FileNotFoundError:
        print("Error: Log file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Use the 'sample.log' file
log_file_path = "sample.log"
detect_suspicious_activity(log_file_path, threshold=10)
