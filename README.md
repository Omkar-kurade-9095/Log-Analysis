## Log Analysis Task

# 1 Crated log file
    create_log_file.py file contains code for how i created log file
# 2 Main file
    main.py file containts:
    - how i parsed the file and obtained :
       # ip_request_count
       # endpoint_count
       # failed_logins
       # ip_address
       # method
       # endpoint
       # protocol
       # status_code
    - iterated throgh log file and created a new .csv file named log_analysis_results.csv 
    - the main method where i called above two methods :
      # def parse_log_file(LOG_FILE):
      # def write_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):
      and done basic operations
# 3 log_analysis_results.csv 
    - Generated .csv file beacause of  "def write_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity):" method
