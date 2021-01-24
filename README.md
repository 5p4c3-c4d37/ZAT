# ZAT
Files here are derived from the ZAT project from SuperCowPowers - https://github.com/SuperCowPowers/zat

Purpose: Modifying ZAT python scripts for more tailored use.

## Todo
- Allow scripts to handle both json string or ascii format zeek logs by importing json2df.py function
    - currently, `dns_clustering.py` and `dns_anomaly_clf.py` only handle json string format
- Create script to cluster http.log and cluster anomalies in http.log
- Develop method to detect base64 encoding or excessively long queries in DNS traffic
