"""Adapted from ZAT project by Brian Wylie of SuperCowPowers - https://github.com/SuperCowPowers/zat"""

from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Zeek Log Conversion
import json
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
from zat import zeek_log_reader


def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json_format',
            help='Import zeek log in json string format',
            action='store_true')
    parser.add_argument('zeek_log_path',
            type=str,
            help='Type in location of zeek log')
    args, commands = parser.parse_known_args()
    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)
    # Sanity check that this is a x509 log
    if 'x509' not in args.zeek_log_path:
        print('This example only works with Zeek x509.log files..')
        sys.exit(1)
    # File may have a tilde in it
    if args.zeek_log_path:
        args.zeek_log_path = os.path.expanduser(args.zeek_log_path)
    # Determine json or ascii format
    if args.json_format:
        print('**Importing zeek log in json format**')
        df = import_json(args.zeek_log_path)
    else:
        print('**Importing zeek log in ascii format**')
        print('**If this hangs for longer than a 17 sec, high chance you are trying to import a log in json format instead, use -j**')
        log_to_df = LogToDataFrame()
        df = log_to_df.create_dataframe(args.zeek_log_path)
    return df

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
    df = parser()

# Check all the x509 Certs for 'Let's Encrypt'/self-signed for potential phishing/malicious sites
    # These domains may be spoofed with a certificate issued by 'Let's Encrypt'
    spoofed_domains = set(['paypal', 'gmail', 'google', 'apple', 'ebay', 'amazon'])
        
    # Modification: List out known ioc domains for testing
    ioc_domains = set(['ioc1', 'ioc2', 'ioc3'])
    # print(df.columns)
    # print(df.index)
    # Run the zeek reader on the x509.log file looking for spoofed domains
    # reader = zeek_log_reader.ZeekLogReader(df, tail=True)  # tail=False to turn off dynamic tailing
    if '@stream' in df.columns:
        field_list = zip(df['ts'], df['id'], df['certificate_issuer'], df['certificate_subject'])
    else:
        field_list = zip(df.index, df['id'], df['certificate.issuer'], df['certificate.subject'])

    for timestamp, ID, issuer, subject in field_list:
        # Include above other fields necessary for testing
            
        if "Let's Encrypt" in issuer:

            # Check if the certificate subject has any spoofed domains
            if any([domain in subject for domain in spoofed_domains]):
                print('\n<<< Suspicious Certificate Found >>>')
                subject = subject[3:]
                issuer = issuer[3:]
                print('Timestamp: ', timestamp)
                print('ID: {:s} \nIssuer: {:s} \nsubject: {:s}'.format(ID, issuer, subject))

            # Below are modifications from the original script.
            elif any([domain in subject for domain in ioc_domains]): # Check against known ioc domains
                print('\n<<< Suspicious Certificate Found >>>')
                print('Timestamp: ', timestamp)
                print('ID: {:s} \nIssuer: {:s} \nsubject: {:s}'.format(ID, issuer, subject))

        if issuer == subject:  # Check for self-signed certificates
            print('\n <<< Self-Signed Certificate Found >>>')
            print('Timestamp: ', timestamp)
            print('ID: {:s} \nIssuer: {:s} \nsubject: {:s}'.format(ID, issuer, subject))


if __name__ == '__main__':
    main()
