#!/usr/bin/env python3

# Commandline arguments
import argparse
# Entropy Calculation
import math
from collections import Counter
# Zeek Log Conversion
import json
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
# Anomaly Detection
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
# Cluster Optimization
from sklearn.manifold import TSNE
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.cluster import DBSCAN
from sklearn.metrics import silhouette_score

def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json_format',
            help='Import zeek log in json string format',
            action='store_true')
    parser.add_argument('-a', '--anomaly',
            help='Perform clustering on anomalies',
            action='store_true')
    parser.add_argument('zeek_log_path',
            type=str,
            help='Type in location of zeek log')
    args = parser.parse_args()
    if args.json_format:
        print('**Importing zeek log in json format**')
        df = import_json(args.zeek_log_path)
    else:
        print('**Importing zeek log in ascii format**')
        print('**If this hangs for longer than a 17 sec, high chance you are trying to import a log in json format instead, use -j**')
        log_to_df = LogToDataFrame()
        df = log_to_df.create_dataframe(args.zeek_log_path)
    return df, args.anomaly

def import_json(path):
    # list of json strings, each log entry is a string
    with open(path) as json_file:
        lines = json_file.readlines()
    # json.loads converts a json string into a dict
    # this is run on each line
    # a dataframe is created from a sequence of dicts using from_records
    df = pd.DataFrame.from_records(map(json.loads, lines))
    return df

def entropy(string):
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def main():
    df, anomaly = parser()

    ######## Preprocessing
    # lengths and entropy will be calculated and added to the dataframe
    df['query_length'] = df['query'].str.len()
    df['answer_length'] = df['answers'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    # Z: "A reserved field that is usually zero in queries and responses."
    features = ['Z', 'proto', 'qtype_name', 'query_length', 'answer_length', 'entropy']
    # normalizes and cleans data for use by models
    to_matrix = DataFrameToMatrix()
    zeek_matrix = to_matrix.fit_transform(df[features])

    ######## Clustering with KMeans
    if anomaly:
        ######## Anomaly Classifer
        # might be worth changing this parameter around to 0.25?
        # leaving blank allows "auto"... hmmm
        odd_clf = IsolationForest(contamination=0.2)
        odd_clf.fit(zeek_matrix)
        predictions = odd_clf.predict(zeek_matrix)
        # create new dataframe with predictions added in
        odd_df = df[features][predictions == -1]
        # select only those that are anomalous
        df = df[predictions == -1].copy()
        zeek_matrix = to_matrix.fit_transform(odd_df)
    num_clusters = min(len(df), 4)
    df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(zeek_matrix)
    # try number of different clusters with silhouette testing
    features += ['query']
    cluster_groups = df[features+['cluster']].groupby('cluster')
    for key, group in cluster_groups:
        print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
        print(group.head())
    return

if __name__ == "__main__":
    main()
