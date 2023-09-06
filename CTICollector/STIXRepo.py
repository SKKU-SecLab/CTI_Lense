import requests
import json
import os

from bs4 import BeautifulSoup
from argparse import ArgumentParser


sinfo = {
  "DigitalSide": {
    "repo":{
      "url":"https://osint.digitalside.it/Threat-Intel/stix2/",
      "tag":"href"
    },
  },
  "JamesBrine": {
    "repo":{
      "url":"https://jamesbrine.com.au/STIX/",
      "tag": "href"
    },
  }
}


def repo_poll(source):
    res = []
    resp = requests.get(sinfo[source]["repo"]["url"]).text
    soup = BeautifulSoup(resp, "html.parser")
    flist = soup.find_all("a", href=True)
    for f in flist:
        if ".json" not in f.text:
            continue
        data_url = sinfo[source]["repo"]["url"] + f.text
        resp = requests.get(data_url)
        res.append(resp.json())
        break

    return res

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-o", type=str, help="Output directory for STIX data", dest="opath", required=True)
    args = parser.parse_args()

    opath = args.opath

    if not opath.endswith("/"):
        opath += "/"

    if not os.path.exists(opath):
        os.mkdir(opath)

    for source,info in sinfo.items():
        print (source)
        if not os.path.exists(opath+source):
            os.mkdir(opath+source)
        data = repo_poll(source)

        for d in data:
            with open(opath+source+"/"+d["id"]+".json", "w") as wf:
                wf.write(json.dumps(d))
        

