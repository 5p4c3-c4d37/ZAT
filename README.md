# ZAT
Files here are derived from the ZAT project from SuperCowPowers - https://github.com/SuperCowPowers/zat

Purpose: Modifying ZAT python scripts for more tailored use.

- `dns_clustering.py` is able to take in both json and ascii format zeek logs (use `-j` for json) and will cluster all entries or just anomalies (use `-a`).
- `dns_length.py` simply prints out dns entries with answer OR query lengths longer than the specified length `-l`.
- `cert_checker_ascii_json.py` is able to take an input .txt file containg iocs seperated by newlines. It checks the certificate issuer and subject for IOCs, Let's Encrpyt, and self-signed certificates.
- `tor_and_port_counter_ascii_json.py ` checks the issuer and subject in the ssl.log for tor connections using a regex search. Use `-t` for dynamic tailing (this feature is under construction).

- NEW: [-d] --directory, allows for a directory of like zeek logs to be parsed into a single dataframe for faster analysis

## Usage
- `python3 dns_clustering.py [-j] [-a] [-d] zeek_log_path`
- `python3 dns_length.py [-j] [-l length] zeek_log_path`
- `python3 cert_checker.py [-h] [-j] [-d] [infile] [outfile] zeek_log_path`
- `python3 tor_and_port_counter_ascii_json.py [-h] [-j] [-d] [-t] zeek_log_path`

## Todo
- `dns_clustering.py`
    - option for user to custom define number of clusters
    - option for just silhouette scoring to determine "optimal" number of clusters
    - option for DBSCAN to recommend number of clusters
    - optimize contamination parameter for isolation forest and try out "auto" setting
- `http_clustering.py`
    - Create script to cluster http.log and cluster anomalies in http.log
- `cert_checker_ascii_json.py`
    - dynamic tailing
- `tor_and_port_counter_ascii_json.py`
    - Add timestamps
    - dynamic tailing
- Develop yara/ZAT functionality
    - see ZAT documentation for examples
- DNS:
    - Develop method to detect base64 encoding or excessively long queries in DNS traffic
        - entropy/regex heuristics to detect base64, cluster based on probability?
        - long queries should be caught by `dns_cluster.py` if they are relatively longer than other entries
    - Create argument that allows analyst to specify the number of characters in DNS record to classify it as "long" or "anomalous"
