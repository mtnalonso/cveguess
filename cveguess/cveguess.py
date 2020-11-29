import cveguess.github as github
import cveguess.nvd as nvd


class CVEGuess:
    def __init__(self, cve):
        self.cve = cve
        self.cve_info = None
        self.related_cves = None

    def get_CVE_info(self):
        self.cve_info = nvd.get_CVE_info(self.cve)
        self.related_cves = {self.cve_info['cve']: self.cve_info}
        return self.cve_info

    def get_related_CVEs(self):
        keyword_search = self.cve_info['vendor'] + '+' + self.cve_info['product']
        self.related_cves = nvd.get_CVEs_by_keyword(keyword_search)
        return self.related_cves

    def get_cve_details(self, limit=0):
        cves = self.related_cves
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
    
        return sorted_cves

