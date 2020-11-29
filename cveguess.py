import argparse
import re

import github
import nvd
import tables




def main():
    args = load_args()

    cve_info = nvd.get_CVE_info(args.cve)

    if args.related:
        cves = get_related_CVEs(cve_info)
    else:
        cves = {cve_info['cve']: cve_info}

    get_cve_details(cves, limit=10)


def load_args():
    parser = argparse.ArgumentParser(prog='cveguess')
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


def get_related_CVEs(cve_info):
    keyword_search = cve_info['vendor'] + '+' + cve_info['product']
    return nvd.get_CVEs_by_keyword(keyword_search)


def get_cve_details(cves, limit=0):
    if limit:
        cves_to_check = {}
        for cve in list(cves.keys())[0:limit]:
            cves_to_check[cve] = cves[cve]
        cves = cves_to_check

    print(f"[*] Analyzing {len(cves)} CVEs")

    for cve in cves.keys():
        cves[cve]['github'] = github.get_details(cve)

    sorted_cves = sorted(
        cves.items(),
        key = lambda x: x[1]['github']['top_stars'],
        reverse=True
    )

    tables.print_cve_details(sorted_cves)
    tables.print_github_details(sorted_cves[0])
    tables.print_cve_table(sorted_cves[0])


if __name__ == '__main__':
    main()
