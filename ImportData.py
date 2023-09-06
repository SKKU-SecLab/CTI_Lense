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

