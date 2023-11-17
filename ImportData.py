import json
import os
from pymongo import MongoClient
from pymongo.database import Database

# Establish a connection to the MongoDB server running on localhost at port 27017
conn = MongoClient(host='localhost', port=27017)

# Create or connect to MongoDB databases for STIX1 and STIX2
stix1_db = conn["STIX1"]
stix2_db = conn["STIX2"]

# Set paths for STIX1 and STIX2 data directories
stix1_path = "dbdata/STIX1/"
stix2_path = "dbdata/STIX2/"

# Process and insert data from STIX1 JSON files into the STIX1 MongoDB database
flist = sorted(os.listdir(stix1_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(stix1_path+f)
    while True:
        try:
            d = json.loads(data.readline())
            stix1_db[f[:-5]].insert_one(d)
        except:
            break

# Process and insert data from STIX2 JSON files into the STIX2 MongoDB database
flist = sorted(os.listdir(stix2_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(stix2_path+f)
    while True:
        try:
            d = json.loads(data.readline())
            stix2_db[f[:-5]].insert_one(d)
        except:
            break

# Create or connect to MongoDB databases for VirusTotal, HybridAnalysis, MetaDefender, and APT_IOC
vt_db = conn["VirusTotal"]
ha_db = conn["HybridAnalysis"]
md_db = conn["MetaDefender"]
apt_db = conn["APT_IOC"]

# Set paths for the data directories of VirusTotal, HybridAnalysis, MetaDefender, and APT_IOC
vt_path = "dbdata/ScanReport/VirusTotal/"
ha_path = "dbdata/ScanReport/HybridAnalysis/"
md_path = "dbdata/ScanReport/MetaDefender/"
apt_path = "dbdata/APT_IOC/"

# Process and insert data from VirusTotal JSON files into the VirusTotal MongoDB database
flist = sorted(os.listdir(vt_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(vt_path+f)
    while True:
        try:
            d = json.loads(data.readline())
            vt_db[f[:-5]].insert_one(d)
        except:
            break

# Process and insert data from HybridAnalysis JSON files into the HybridAnalysis MongoDB database
flist = sorted(os.listdir(ha_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(ha_path+f)
    while True:
        try:
            d = json.loads(data.readline())
            ha_db[f[:-5]].insert_one(d)
        except:
            break

# Process and insert data from MetaDefender JSON files into the MetaDefender MongoDB database
flist = sorted(os.listdir(md_path))
for f in flist:
    if not f.endswith(".json"):
        continue
    data = open(md_path+f)
    while True:
        try:
            d = json.loads(data.readline())
            md_db[f[:-5]].insert_one(d)
        except:
            break

# Process and insert data from APT_IOC JSON files into the APT_IOC MongoDB database
flist = sorted(os.listdir(apt_path))
for f in flist:
    # Skip files that do not have a ".json" extension
    if not f.endswith(".json"):
        continue
    data = open(apt_path+f)
    while True:
        try:
            d = json.loads(data.readline())
            apt_db[f[:-5]].insert_one(d)
        except:
            break
