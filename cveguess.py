import argparse
import json
import re

import requests
from bs4 import BeautifulSoup
from rich import print as rprint


nvd_cve_api_url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/{}'
nvd_cves_api_keyword_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={}'


def main():
    args = load_args()

    cve_info = get_CVE_info(args.cve)

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
    return get_CVEs_by_keyword(keyword_search)


def get_CVEs_by_keyword(keyword):
    print(f'[+] Downloading CVE list for "{keyword}"...')
    keyword_search = keyword
    url = nvd_cves_api_keyword_url.format(keyword_search)

    response = requests.get(url)
    cve_items = json.loads(response.content)['result']['CVE_Items']

    cves = {}

    for cve_item in cve_items:
        cve_details = parse_nvd_CVE_item(cve_item)
        cves[cve_details['cve']] = cve_details

    return cves


def get_CVE_info(cve):
    response = requests.get(nvd_cve_api_url.format(cve))
    response = json.loads(response.content)
    cve_item = response['result']['CVE_Items'][0]
    return parse_nvd_CVE_item(cve_item)


def parse_nvd_CVE_item(cve_item):
    cve = cve_item['cve']['CVE_data_meta']['ID']
    description = cve_item['cve']['description']['description_data'][0]['value']

    try:
        score = cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
        severity = cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    except KeyError:
        score = None
        severity = None

    try:
        cpe = cve_item['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri']
        vendor = cpe.split(':')[3]
        product = cpe.split(':')[4]
    except KeyError:
        cpe = None
        vendor = None
        product = None

    details = {
        'cve': cve,
        'cpe': cpe,
        'description': description,
        'score': score,
        'severity': severity,
        'vendor': vendor,
        'product': product,
    }
    return details


def get_cve_details(cves, limit=0):
    if limit:
        cves_to_check = {}
        for cve in list(cves.keys())[0:limit]:
            cves_to_check[cve] = cves[cve]
        cves = cves_to_check

    print(f"[*] Analyzing {len(cves)} CVEs")

    for cve in cves.keys():
        cves[cve]['github'] = get_github_details(cve)

    sorted_cves = sorted(
        cves.items(),
        key = lambda x: x[1]['github']['top_stars'],
        reverse=True
    )

    tables.print_cve_details(sorted_cves)
    tables.print_github_details(sorted_cves[0])
    tables.print_cve_table(sorted_cves[0])


def get_github_details(cve):
    print(f"[*] Gathering Github details for {cve}")
    details = {}
    url = f"https://github.com/search?q={cve}&type=repositories"

    response = requests.get(url)
    
    if response.status_code == 429:
        rprint("[bold magenta][*] WARNING:[/bold magenta] too many requests!")
    soup = BeautifulSoup(response.content, 'html.parser')

    repository_entries = soup.findAll('li', {'class': 'repo-list-item'})

    details['total_repos'] = len(repository_entries)
    details['top_stars'] = 0
    repositories = []

    for entry in repository_entries:
        links = entry.findAll('a')

        repo_link = links[0]

        try:
            stars = int(links[1].text.strip())
        except (IndexError, ValueError):
            stars = 0

        repository = {
            'name': repo_link.text,
            'url': f"https://github.com{repo_link['href']}",
            'stars': stars,
        }

        if stars >= details['top_stars']:
            details['top_stars'] = stars

        repositories.append(repository)

    if repositories:
        details['repositories'] = sorted(repositories, key = lambda x: x['stars'], reverse=True)

    return details



if __name__ == '__main__':
    main()
