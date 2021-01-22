"""Adapted from ZAT project by Brian Wylie of SuperCowPowers - https://github.com/SuperCowPowers/zat"""

from __future__ import print_function
import os
import sys
import argparse
from pprint import pprint

# Local imports
from zat import zeek_log_reader
import pandas as pd

if __name__ == '__main__':
    # Example to check all the x509 Certs from 'Let's Encrypt' for potential phishing/malicious sites

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str, help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a dns log
    if 'x509' not in args.zeek_log:
        print('This example only works with Zeek x509.log files..')
        sys.exit(1)

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # These domains may be spoofed with a certificate issued by 'Let's Encrypt'
        spoofed_domains = set(['paypal', 'gmail', 'google', 'apple', 'ebay', 'amazon'])
        
        # Modification: List out known ioc domains for testing
        ioc_domains = set(['ioc1', 'ioc2', 'ioc3'])

        # Run the zeek reader on the x509.log file looking for spoofed domains
        reader = zeek_log_reader.ZeekLogReader(args.zeek_log, tail=True)  # tail=False to turn off dynamic tailing
        for row in reader.readrows():

            # Pull out specified fields, i.e. Certificate Issuer
            issuer = row['certificate.issuer']
            subject = row['certificate.subject']
            
            # Include here other fields necessary for testing
            
            if "Let's Encrypt" in issuer:

                # Check if the certificate subject has any spoofed domains

                if any([domain in subject for domain in spoofed_domains]):
                    print('\n<<< Suspicious Certificate Found >>>')
                    #pprint(row)
                    spoofed_df = pd.DataFrame.from_dict(row, orient='index') # Modified to print as pandas dataframe rather than pyton dict
                    print(spoofed_df)
                    
         # Below are modifications from the original script.           
                elif any([domain in subject for domain in ioc_domains]): # Check against known ioc domains
                    print('\n<<< Suspicious Certificate Found >>>')
                    # pprint(row)
                    ioc_df = pd.DataFrame.from_dict(row, orient='index')
                    print(ioc_df)
            if issuer == subject:  # Check for self-signed certificates
                print('\n <<< Self-Signed Certificate Found >>>')
                # pprint(row)
                selfsigned_df = pd.DataFrame.from_dict(row, orient='index')
                print(selfsigned_df)
