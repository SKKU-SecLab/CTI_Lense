import os
import json
import wget
import requests

from bs4 import BeautifulSoup
from argparse import ArgumentParser


def get_file_list(name, url):
    res = []
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    pagelist = soup.find_all("a")

    for page in pagelist:
        if page["href"].endswith(".json"):
            res.append(url+page["href"])
            break
    return res

repo_info = {
    "OSINT":"https://www.circl.lu/doc/misp/feed-osint/",
    "DigitalSide":"https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/",
    "Bazaar":"https://bazaar.abuse.ch/downloads/misp/",
    "Botvrij":"https://www.botvrij.eu/data/feed-osint/",
    "ThreatFox":"https://threatfox.abuse.ch/downloads/misp/",
    "URLhaus":"https://urlhaus.abuse.ch/downloads/misp/"
}

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-o", type=str, help="Output directory for STIX data", dest="opath", required=True)
    args = parser.parse_args()

    opath = args.opath

    if not opath.endswith("/"):
        opath += "/"

    if not os.path.exists(opath):
        os.mkdir(opath)

    for name, url in repo_info.items():
        rpath = opath+name

        if not os.path.exists(opath+name):
            os.mkdir(rpath)

        print (name, url)
        file_list = get_file_list(name,url)

        for f in file_list:
            wget.download(f,out=rpath)
            # data = requests.get(f).text


    # break

