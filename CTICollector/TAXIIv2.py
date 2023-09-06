import requests
import json
import datetime
import os

from taxii2client.v20 import Server, Collection, as_pages, Status
from argparse import ArgumentParser
from cytaxii2 import cytaxii2

serverinfo = {
  "Unit42":{
    "surl":"https://stix2.unit42.org/taxii/",
    "id": "USER_ID",
    "pw": "USER_PASSWORD"
  },
  "IBM X-Force":{
    "apikey": "USER_API_KEY",
    "collections":["public"]
  }
}

def taxii2(source):
    res = []
    server = Server(serverinfo[source]["surl"],
                    user=serverinfo[source]["id"], password=serverinfo[source]["pw"])

    api_root = server.api_roots[0]

    for collection in api_root.collections:
        for bundle in as_pages(collection.get_objects, per_request=50):
            res.append(bundle)

    return res

def xforce_taxii2(source, stime=None, etime=None):
    res = []
    headers = {
        'accept': 'application/vnd.oasis.taxii+json; version=2.0',
        'Authorization': 'Basic {}'.format(serverinfo[source]["apikey"])
    }

    for collection in serverinfo[source]["collections"]:
        url = 'https://api.xforce.ibmcloud.com/api/taxii2/collections/{}/objects?' \
              'added_after={}&added_before={}'.format(collection, stime, etime)
        try:
            response = requests.get(url, headers=headers)
            bundle = response.json()
            res.append(bundle)
        except:
            print ("Can't get STIX data")

    return res

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("-s", type=str, help="Start datetime for collecting the STIX data (e.g., 2022-01-01)", dest="stime", required=True)
    parser.add_argument("-e", type=str, help="End datetime for collecting the STIX data (e.g., 2023-01-01)", dest="etime", required=True)
    parser.add_argument("-o", type=str, help="Output directory for STIX data", dest="opath", required=True)


    args = parser.parse_args()

    stime = datetime.datetime.strptime(args.stime,"%Y-%m-%d")
    stime = stime.replace(tzinfo=datetime.timezone.utc)
    etime = datetime.datetime.strptime(args.etime,"%Y-%m-%d")
    etime = etime.replace(tzinfo=datetime.timezone.utc)
    opath = args.opath

    if not opath.endswith("/"):
        opath += "/"

    if not os.path.exists(opath):
        os.mkdir(opath)
        os.mkdir(opath+"Unit42")
        os.mkdir(opath+"IBMxForce")

    unit42 = taxii_poll("Unit42")
    xforce = xforce_taxii2("IBM X-Force", stime=stime, etime=etime)

    for i in range(len(unit42)):
        with open(opath+"Unit42/"+str(i)+".json", "w") as wf:
            wf.write(json.dumps(unit42[i]))

    for i in range(len(xforce)):
        with open(opath+"IBMxForce/"+str(i)+".json", "w") as wf:
            wf.write(json.dumps(xforce[i]))
