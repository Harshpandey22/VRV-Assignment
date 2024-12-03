import re
import csv
from collections import defaultdict


def parse_log_file(log_file, failed_login_threshold=1):  # Lowered threshold for testing, we can use 10 according to assignment
    """
    Parse log file and extract key metrics.

    Args:
        log_file (str): Path to log file
        failed_login_threshold (int): Threshold for suspicious login attempts

    Returns:
        Tuple of dictionaries with IP requests, endpoint requests, and failed login attempts
    """
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue

            ip = ip_match.group(1)
            ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"[A-Z]+ (/[^ ]*) HTTP', line)
            if endpoint_match:
                endpoint_requests[endpoint_match.group(1)] += 1

            # Track failed login attempts (check for '401' or 'Invalid credentials')
            if '401' in line or 'Invalid credentials' in line or 'Authentication failed' in line:
                failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts


def print_results(ip_requests, endpoint_requests, failed_login_attempts, failed_login_threshold):
    """
    Print detailed analysis results to console.

    Args:
        ip_requests (dict): IP request counts
        endpoint_requests (dict): Endpoint access counts
        failed_login_attempts (dict): Failed login attempts per IP
    """
    # Print Requests per IP
    print("\nRequests per IP Address:")
    print("IP Address".ljust(20) + "Request Count")
    print("-" * 35)
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip.ljust(20)}{count}")

    # Print Most Accessed Endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Print Suspicious Activity
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > failed_login_threshold}
    print("\nSuspicious Activity Detected:")
    print("IP Address".ljust(20) + "Failed Login Attempts")
    print("-" * 35)
    if suspicious_ips:
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip.ljust(20)}{count}")
    else:
        print("No suspicious activity detected.")


def save_results_to_csv(ip_requests, endpoint_requests, failed_login_attempts, failed_login_threshold):
    """
    Save analysis results to CSV file.

    Args:
        ip_requests (dict): IP request counts
        endpoint_requests (dict): Endpoint access counts
        failed_login_attempts (dict): Failed login attempts per IP
        failed_login_threshold (int): Threshold for suspicious login attempts
    """
    with open('log_analysis_results.csv', 'w', newline='') as file:
        writer = csv.writer(file)

        # Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])

        # Most Accessed Endpoint
        most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        # Suspicious Activity
        suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > failed_login_threshold}
        writer.writerow(['IP Address', 'Failed Login Count'])
        if suspicious_ips:
            for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])
        else:
            writer.writerow(["No suspicious activity detected."])


def main():
    """
    Main function to execute log analysis.
    """
    try:
        # Load the Log file
        log_File = r"C:\Users\harsh\Desktop\VRV Assignment\sample.log"
        # Process log file
        ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(log_File)

        # Print results to console
        print_results(ip_requests, endpoint_requests, failed_login_attempts, failed_login_threshold=1)

        # Save results to CSV
        save_results_to_csv(ip_requests, endpoint_requests, failed_login_attempts, failed_login_threshold=1)

        print("\nAnalysis complete. Results saved to log_analysis_results.csv")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
