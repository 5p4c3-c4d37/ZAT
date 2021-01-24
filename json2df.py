#!/usr/bin/env python3

import json
import pandas as pd

def import_json():
    path = input("Type in the location of the zeek log: ")
    # list of json strings, each log entry is a string
    with open(path) as json_file:
        lines = json_file.readlines()

    # json.loads converts a json string into a dict
    # this is run on each line
    # a dataframe is created from a sequence of dicts using from_records
    df = pd.DataFrame.from_records(map(json.loads, lines))
    return df 

def main():
    df = import_json()
    return

if __name__ == "__main__":
    main()
