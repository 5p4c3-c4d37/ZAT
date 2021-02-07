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
from contextlib import redirect_stdout


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
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json_format',
            help='Import zeek log in json string format',
            action='store_true')
    parser.add_argument('-d', '--directory',
            help='Import zeek logs from directory',
            action='store_true')
    parser.add_argument('infile', nargs='?',
            type=argparse.FileType('r'),
            default=sys.stdin,
            help='File path to txt IOC File. One IOC per line')
    parser.add_argument('outfile', nargs='?',
            type=argparse.FileType('w'),
            default=sys.stdout,
            help='Output file and path')
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
    # Files may have a tilde in it
    if args.zeek_log_path:
        args.zeek_log_path = os.path.expanduser(args.zeek_log_path)
    if args.infile:
        infile = args.infile.read().splitlines()
        # ioc = infile.read()
    if args.outfile:
        outfile = args.outfile
    # Determine json or ascii format
    if args.json_format:
        if args.directory:
            print('**Importing zeek logs from directory in json format**')
            zeek_logs = [os.path.join(args.zeek_log_path, file) for file in os.listdir(args.zeek_log_path)]
            logs = []
            for log in zeek_logs:
                logs.append(import_json(log))
            df = pd.concat(logs)
        else:
            print('**Importing zeek log in json format**')
            df = import_json(args.zeek_log_path)
        field_list = zip(df['ts'], df['id'], df['certificate_issuer'], df['certificate_subject'])
    else:
        if args.directory:
            print('**Importing zeek logs from directory in ascii format**')
            zeek_logs = [os.path.join(args.zeek_log_path, file) for file in os.listdir(args.zeek_log_path)]
            logs = []
            log_to_df = LogToDataFrame()
            for log in zeek_logs:
                logs.append(log_to_df.create_dataframe(log))
            df = pd.concat(logs)
        else:
            print('**Importing zeek log in ascii format**')
            print('**Hanging? High chance you are trying to import a log in json format, use -j**')
            log_to_df = LogToDataFrame()
            df = log_to_df.create_dataframe(args.zeek_log_path)
        field_list = zip(df.index, df['id'], df['certificate.issuer'], df['certificate.subject'])

    # Check all the x509 Certs for 'Let's Encrypt'/self-signed for potential phishing/malicious sites
    # These domains may be spoofed with a certificate issued by 'Let's Encrypt'
    # print(df.columns)
    # print(df.index)
    # Run the zeek reader on the x509.log file looking for spoofed domains
    # reader = zeek_log_reader.ZeekLogReader(df, tail=True)  # tail=False to turn off dynamic tailing
    for timestamp, ID, issuer, subject in field_list:
        # Include above other fields necessary for testing
        spoofed_domains = set(['paypal', 'gmail', 'google', 'apple', 'ebay', 'amazon'])
        # print(spoofed_domains)
        if "Let's Encrypt" in issuer:
        # Check if the certificate subject has any spoofed domains
            if any([domain in subject for domain in spoofed_domains]):
                subject = subject[3:]
                issuer = issuer[3:]
                with redirect_stdout(outfile):
                    print('\n<<< Suspicious Certificate Found >>>')
                    print('Timestamp: ', timestamp)
                    print('ID: {:s} \nIssuer: {:s} \nsubject: {:s}'.format(ID, issuer, subject))

        if issuer == subject:  # Check for self-signed certificates
            subject = subject[3:]
            issuer = issuer[3:]
            with redirect_stdout(outfile):
                print('\n <<< Self-Signed Certificate Found >>>')
                print('Timestamp: ', timestamp)
                print('ID: {:s} \nIssuer: {:s} \nsubject: {:s}'.format(ID, issuer, subject))

        if args.infile:
            ioc_domains = infile
            # print(ioc_domains)
            if any([ioc in (subject or issuer) for ioc in ioc_domains]):
                with redirect_stdout(outfile):
                    print('\n <<< IOC Found >>>')
                    print('Timestamp: ', timestamp)
                    print('ID: {:s} \nIssuer: {:s} \nsubject: {:s}'.format(ID, issuer, subject))


if __name__ == '__main__':
    main()
