import json

import requests


nvd_cve_api_url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/{}'
nvd_cves_api_keyword_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={}'


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
