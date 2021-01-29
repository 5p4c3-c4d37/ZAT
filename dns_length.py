#!/usr/bin/env python3

# Commandline arguments
import argparse
# Zeek Log Conversion
import json
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix

def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json_format',
            help='Import zeek log in json string format',
            action='store_true')
    parser.add_argument('-l', '--length',
            help='Filter queries that have characters greater than this length',
            type=int,
            default=0)
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
    return df, args.length

def import_json(path):
    # list of json strings, each log entry is a string
    with open(path) as json_file:
        lines = json_file.readlines()
    # json.loads converts a json string into a dict
    # this is run on each line
    # a dataframe is created from a sequence of dicts using from_records
    df = pd.DataFrame.from_records(map(json.loads, lines))
    return df

def main():
    df, length = parser()

    df['query_length'] = df['query'].str.len()
    df['answer_length'] = df['answers'].str.len()

    # full list of possible columns to print, choose wisely
    '''
    display_df = df['id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p',
            'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
            'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
            'RA', 'Z', 'answers', 'TTLs', 'rejected', 'query_length', 'answer_length']
    '''
    display_df = df[['id_orig_h', 'id_orig_p', 'id_resp_h', 'id_resp_p', 'query', 'answers',
            'query_length', 'answer_length']]

    # options to change if you want to see everything, otherwise will be cut off in terminal
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    #pd.set_option('display.max_colwidth', None)

    print(display_df[(display_df['query_length'] >= length) | (display_df['answer_length'] >= length)])
    return

if __name__ == "__main__":
    main()
