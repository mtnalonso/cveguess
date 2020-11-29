import argparse
import re

import cveguess.tables as tables
from cveguess import CVEGuess


def main():
    args = load_args()

    cveguess = CVEGuess(args.cve)
    cve_info = cveguess.get_CVE_info()

    if args.related:
        cves = cveguess.get_related_CVEs()

    cves_details = cveguess.get_cve_details(limit=10)
    print_tables(cves_details)


def load_args():
    parser = argparse.ArgumentParser(
        prog='cveguess',
        description="CVE exploit guesser"
    )
    parser.add_argument(
        '-r',
        '--related',
        action='store_true',
        help='Gather related CVEs'
    )
    parser.add_argument(
        'cve',
        metavar='CVE',
        type=cve_type
    )
    return parser.parse_args()


def cve_type(arg_value, pat=re.compile('CVE-\d{4}-\d{4,7}')):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError('Wrong CVE format')
    return arg_value


def print_tables(cves_details):
    tables.print_cve_details(cves_details)
    tables.print_github_details(cves_details[0])
    tables.print_cve_table(cves_details[0])
