from rich.console import Console
from rich.table import Table


def print_cve_details(cves):
    table = Table(title='CVE details')

    table.add_column('CVE', justify='left', style='cyan', no_wrap=True)
    table.add_column('Max Github stars')

    for cve, details in cves:   
        table.add_row(cve, str(details['github']['top_stars']))

    console = Console()
    console.print(table)
    return


def print_github_details(cve):
    cve, details = cve
    table = Table(title=f"Github entries for {cve}")

    table.add_column('Repository', no_wrap=True)
    table.add_column('URL', no_wrap=True)
    table.add_column('Stars', justify='center')

    for repo in details['github']['repositories']:
        link = "[link={0}]{0}[/link]".format(repo['url'])
        table.add_row(repo['name'], link, str(repo['stars']))

    console = Console()
    console.print(table)


def print_cve_table(cve_details):
    cve, details = cve_details
    table = Table(title=f"Details for {cve}")

    table.add_column()
    table.add_column(cve)

    table.add_row('Description', details['description'])
    table.add_row('Score', str(details.get('score', '')))
    table.add_row('Vendor', details.get('vendor'))
    table.add_row('Product', details.get('product'))
    table.add_row('CPE', details.get('cpe'))

    console = Console()
    console.print(table)
