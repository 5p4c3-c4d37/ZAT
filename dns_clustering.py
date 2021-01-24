#!/usr/bin/env python3

import json
import pandas as pd

def import_json():
    path = input("Type in the location of the zeek log: ")
    if path == "":
        path = "zeek_logs/NASHUA/dns.log"
    # list of json strings, each log entry is a string
    with open(path) as json_file:
        lines = json_file.readlines()

    # json.loads converts a json string into a dict
    # this is run on each line
    # a dataframe is created from a sequence of dicts using from_records
    df = pd.DataFrame.from_records(map(json.loads, lines))
    return df

import math
from collections import Counter

def entropy(string):
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

from zat.dataframe_to_matrix import DataFrameToMatrix
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans

def main():
    df = import_json()

    ######## Preprocessing

    # lengths and entropy will be calculated and added to the dataframe
    df['query_length'] = df['query'].str.len()
    df['answer_length'] = df['answers'].str.len()
    df['entropy'] = df['query'].map(lambda x: entropy(x))
    # Z: "A reserved field that is usually zero in queries and responses."
    features = ['Z', 'proto', 'qtype_name', 'query_length', 'answer_length', 'entropy']

    to_matrix = DataFrameToMatrix()
    # normalizes and cleans data for use by models
    zeek_matrix = to_matrix.fit_transform(df[features])
    #print(zeek_matrix.shape)

    ######## Clustering with KMeans

    # try number of different clusters with silhouette testing
    num_clusters = min(len(df), 4)
    df['cluster'] = KMeans(n_clusters=num_clusters).fit_predict(zeek_matrix)

    features += ['query']
    cluster_groups = df[features+['cluster']].groupby('cluster')

    for key, group in cluster_groups:
        print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
        print(group.head())

    return

if __name__ == "__main__":
    main()
