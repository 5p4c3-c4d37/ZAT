"""Tor detection and SSL port count example"""
from __future__ import print_function
import os
import sys
import argparse
import re
from collections import Counter
from pprint import pprint

# Local imports
import json
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
from zat import zeek_log_reader

    # Example to check for potential Tor connections and give a summary of different ports
    # used for SSL connections. Please note that your Zeek installation must stamp the
    # ssl.log file with the 'issuer' field. More info can be found here:
    # https://docs.zeek.org/en/master/script-reference/proto-analyzers.html#zeek-ssl


def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json_format',
            help='Import zeek log in json string format',
            action='store_true')
    parser.add_argument('zeek_log_path',
            type=str,
            help='Type in location of zeek log')
    parser.add_argument('-t',
            action='store_true',
            default=False,
            help='Sets the program to tail a live Zeek log')
    args, commands = parser.parse_known_args()
    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)
    # Sanity check that this is a ssl log
    if 'ssl' not in args.zeek_log_path:
        print('This example only works with Zeek ssl.log files..')
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
    # A counter for possible Tor connections
    number = 0
    # A empty list to use for the port statistics
    ports = []

    # Set up the regex search that is used against the issuer field
    issuer_regex = re.compile('CN=www.\w+.com')
    # Set up the regex search that is used against the subject field
    subject_regex = re.compile('CN=www.\w+.net')

    # Need to figure out what to do with the tail argument here
    # Run the zeek reader on the ssl.log file looking for potential Tor connections
    # reader = zeek_log_reader.ZeekLogReader(args.zeek_log, tail=args.t)

    # Test to make sure ssl.log is stamped with issuer/subject fields
    try:
        issuer_test = df['issuer']
    except KeyError:
        print('Could not find the issuer field in your ssl.log. Please verify your log file.')
        sys.exit(1)
    try:
        subject_test = df['subject']
    except KeyError:
        print('Could not find the subject field in your ssl.log. Please verify your log file.')
        sys.exit(1)

    # Change syntax of fields based off ascii and json formats
    if '@stream' in df.columns:
        field_list = zip(df['id_orig_h'], df['id_resp_h'], df['id_resp_p'], df['issuer'], df['subject'])
    else:
        field_list = zip(df['id.orig_h'], df['id.resp_h'],  df['id.resp_p'], df['issuer'], df['subject'])

    for source, dest, port, issuer, subject in field_list:
        # Add the destination port to the list of ports
        ports.append(port)
        # Pull out the Certificate Issuer
        # Check if the issuer matches the known Tor format
        # print(df.columns)
        # print(df.index)
        if issuer_regex.match(str(issuer)):
            if subject_regex.match(str(subject)):
            # Check if the subject and issuer match the known Tor format
                print('\nPossible Tor connection found')
                print('From: {:s} To: {:s} Port: {:d}'.format(source, dest, port))
                number += 1

        # If we are not tailing a live log file, let's print some stats.
        # if not args.t:
    # First let's print (if any) the number of possible Tor connections that were found
    print('\nTotal number of possible Tor connections found: {:d}'.format(number))
    # Now let's do the stats on and printing of the port count
    portcount = Counter(ports)
    print('\nPort statistics')
    for port, count in portcount.most_common():
        print('{:<7} {:d}'.format(port, count))


if __name__ == '__main__':
    main()
