import csv
from collections import defaultdict, Counter


FAILED_LOGIN_THRESHOLD = 10

LOG_FILE = "C:/Users/omkar/OneDrive/Desktop/ML/Projects/Log Analysis/sample.log"
OUTPUT_CSV = "log_analysis_results.csv"


def parse_log_file(LOG_FILE):
    ip_request_count = Counter()
    endpoint_count = Counter()
    failed_logins = defaultdict(int)

    with open(LOG_FILE, 'r') as file:
        for line in file:
            parts = line.split()
            #print(parts)
            if len(parts) < 9:
                continue 
            
            ip_address = parts[0]
            method, endpoint, protocol = parts[5], parts[6], parts[7]
            #print(method,endpoint,protocol)
            status_code = parts[8]
            #print(parts[8])
            message = " ".join(parts[9:]).strip('"')
            
            
            ip_request_count[ip_address] += 1
            
           
            endpoint_count[endpoint] += 1
            
            
            if status_code == "401" or "Invalid credentials" in message:
                failed_logins[ip_address] += 1

    return ip_request_count, endpoint_count, failed_logins


def write_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity:
            writer.writerow([ip, count])


def main():
    ip_request_count, endpoint_count, failed_logins = parse_log_file(LOG_FILE)

    sorted_ip_requests = ip_request_count.most_common()
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:20} {count}")

    most_accessed_endpoint = endpoint_count.most_common(1)[0]
    print(f"\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    suspicious_activity = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity:
        print(f"{ip:20} {count}")

   
    write_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activity)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
