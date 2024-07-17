# Analyzing-DNS-Log-Files-Using-Splunk-SIEM 

# Introduction

DNS (Domain Name System) logs are crucial for understanding network activity and identifying potential security threats. Splunk SIEM (Security Information and Event Management) provides powerful capabilities for analyzing DNS logs and detecting anomalies or malicious activities.
## Steps to Analyze DNS Log Files in Splunk SIEM
### 1. Search for DNS Event
-   Open Splunk interface and navigate to the search bar.
-   Enter the following search query to retrieve DNS events
-   
![Opera Snapshot_2024-07-17_203827_127 0 0 1](https://github.com/user-attachments/assets/4d35ed31-fd2c-4a08-9296-b3a526be8c5e)


### 2. Extract Relevant Fields
-   Identify key fields in DNS logs such as source IP, destination IP, domain name, query type, response code, etc.
-   As mentioned below, | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b": This regex searches for common DNS-related keywords in the raw event data.
-   Example extraction command:
-   ![Opera Snapshot_2024-07-17_203700_www youtube com](https://github.com/user-attachments/assets/2045981b-2286-4222-a668-4494b80e41b3)
### 3. Identify Anomalies
-   Look for unusual patterns or anomalies in DNS activity.
-   Example query to identify spikes
- `index=_* OR index=* sourcetype=dns_sample  | stats count by record`
### Find the top DNS sources
-  Use the top command to count the occurrences of each query type:
 ````
index=* sourcetype=dns_sample | top fqdn, src_ip
````
### 5. Investigate Suspicious Domains
-   Search for domains associated with known malicious activity or suspicious behavior.
-   Utilize threat intelligence feeds or reputation databases to identify malicious domains such virustotal.com
-   Example search for known malicious domains:
- `index=* sourcetype=dns_sample fqdn="maliciousdomain.com"`

## Conclusion
Analyzing DNS log files using Splunk SIEM enables security professionals to detect and respond to potential security incidents effectively. By understanding DNS activity and identifying anomalies, organizations can enhance their overall security posture and protect against various cyber threats.
