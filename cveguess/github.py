import requests
from bs4 import BeautifulSoup
from rich import print as rprint


def get_details(cve):
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

