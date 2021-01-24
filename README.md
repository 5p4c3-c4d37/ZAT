# ZAT
Files here are derived from the ZAT project from SuperCowPowers - https://github.com/SuperCowPowers/zat

Purpose: Modifying ZAT python scripts for more tailored use.

`dns_clustering.py` is able to take in both json and ascii format zeek logs (use `-j` for json) and will cluster all entries or just anomalies (use `-a`)

## Usage
`python3 dns_clustering.py [-j] [-a] zeek_log_path`

## Todo
- add silhouette scoring to determine "optimal" number of clusters
- optimize contamination parameter for isolation forest and try out "auto" setting
- Create script to cluster http.log and cluster anomalies in http.log
- Develop method to detect base64 encoding or excessively long queries in DNS traffic
    - entropy/regex heuristics to detect base64, cluster based on probability?
    - long queries should be caught by `dns_cluster.py` if they are relatively longer than other entries
