import json
import os

from pymongo import MongoClient
from pymongo.database import Database


conn = MongoClient(host='localhost', port=27017)

stix1_db = conn["STIX1"]
stix2_db = conn["STIX2"]

stix1_path = "dbdata/STIX1/"
stix2_path = "dbdata/STIX2/"

flist1 = sorted(os.listdir(stix1_path))

for f in flist1:
    if not f.endswith(".json"):
        continue
    data = open(stix1_path+f).read().split("\n")[:-1]
    dlist = [json.loads(d) for d in data]
    stix1_db[f[:-5]].insert_many(dlist)

flist2 = sorted(os.listdir(stix2_path))

for f in flist2:
    if not f.endswith(".json"):
        continue
    data = open(stix2_path+f).read().split("\n")[:-1]
    dlist = [json.loads(d) for d in data]
    stix2_db[f[:-5]].insert_many(dlist)

vt_db = conn["VirusTotal"]
vt_path = "dbdata/ScanReport/VirusTotal/"
flist = sorted(os.listdir(vt_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(vt_path+f).read().split("\n")[:-1]
    dlist = [json.loads(d) for d in data]
    vt_db[f[:-5]].insert_many(dlist)

ha_db = conn["HybridAnalysis"]
ha_path = "dbdata/ScanReport/HybridAnalysis/"
flist = sorted(os.listdir(ha_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(ha_path+f).read().split("\n")[:-1]
    dlist = [json.loads(d) for d in data]
    ha_db[f[:-5]].insert_many(dlist)

md_db = conn["MetaDefender"]
md_path = "dbdata/ScanReport/MetaDefender/"
flist = sorted(os.listdir(md_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(md_path+f).read().split("\n")[:-1]
    dlist = [json.loads(d) for d in data]
    md_db[f[:-5]].insert_many(dlist)

apt_db = conn["APT_IOC"]
apt_path = "dbdata/APT_IOC/"
flist = sorted(os.listdir(apt_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(apt_path+f).read().split("\n")[:-1]
    dlist = [json.loads(d) for d in data]
    apt_db[f[:-5]].insert_many(dlist)

