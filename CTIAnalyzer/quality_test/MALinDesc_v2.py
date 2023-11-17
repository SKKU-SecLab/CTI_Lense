import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json
import os

path = os.path.dirname(os.path.abspath(__file__))

# Function to retrieve Malware instances in Malware objects mentioned in the 'report' collection based on a description query in STIX 2.
def getMALinDesc(dbdup, mallist):
    col = "report"
    lenlist = len(mallist)
    
    res = []
    # MongoDB query to find documents in the 'report' collection where the description contains keywords related to malware
    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"}
    }

    MALinDes1 = list(dbdup[col].find(query))
    
    cnt = 0
    for rep in MALinDes1:
        for obj in rep["object_refs"]:
            if "indicator" in obj:
                res.append(obj)

    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"}
    }

    MALinDes2 = list(dbdup[col].find(query))

    for rep in MALinDes2:
        for obj in rep["object_refs"]:
            if "indicator" in obj:
                res.append(obj)

    
    return len(set(res))

def getMALinDescSrc(dbdup, mallist):
    col = "report"
    lenlist = len(mallist)
    
    srclist = db[col].distinct("source")

    for src in srclist:
        print (src)
        res = []
        query = {
            "description":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"},
            "source": src
        }

        MALinDes1 = list(dbdup[col].find(query))
    
        cnt = 0
        for rep in MALinDes1:
            for obj in rep["object_refs"]:
                if "indicator" in obj:
                    res.append(obj)

        query = {
            "description":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"},
            "source":src
        }

        MALinDes2 = list(dbdup[col].find(query))

        for rep in MALinDes2:
            for obj in rep["object_refs"]:
                if "indicator" in obj:
                    res.append(obj)

        print (len(set(res)))



def getValidMAL(db, mallist):
    col = "indicator"
    lenlist = len(mallist)
    cnt = 0
    res = []

    # Query to count the number of Indicator objects with valid objects/attributes (label).
    query = {
        "labels":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"}
    }
    for obj in list(db[col].find(query)):
        res.append(obj["_id"])

    query = {
        "labels":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"}
    }

    for obj in list(db[col].find(query)):
        res.append(obj["_id"])

    return len(set(res))

def getValidMALSrc(db, mallist):
    col = "indicator"
    
    lenlist = len(mallist)
    cnt = 0
    
    srclist = db[col].distinct("source")
    
    for src in srclist:
        print (src)
        res = []

        query = {
            "labels":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"},
            "source":src
        }
        for obj in list(db[col].find(query)):
            res.append(obj["_id"])

        query = {
            "labels":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"},
            "source":src
        }

        for obj in list(db[col].find(query)):
            res.append(obj["_id"])

        print (len(set(res)))


def run():
    host = "localhost"
    port = 27017

    dbname = "STIX2"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    # Get the keywords for Malware instances
    mallist = open(path+"/dictionary/MALlist.txt").read().split("\n")[:-1]

    stmallist = []

    # Set additional frequently used malware information.
    endwith_keyword = [" rat", " stealer", " ransom", " ransomware", " trojan",
                   " botnet", " pos", " downloader", " locker", " rootkit",
                   " worm", " logger", " keylogger", " clipper", " backdoor",
                   " webshell", " spy", " tds"]
    stawith_keyword = ["win.", "win32.", "win/", "win32/", "backdoor.",
                       "trojan.", "elf.", "android/", "mal/", "osx/",
                       "androidos/"]

    # set the final malware instance ketwords
    for mal in mallist:
        stmallist.append(mal)
        for key in endwith_keyword:
            if mal.endswith(key):
                stmallist.append(mal.replace(key,""))

        for key in stawith_keyword:
            if mal.startswith(key):
                stmallist.append(mal.replace(key,""))

    stmallist = list(set(stmallist))
    
    _stmallist = [mal for mal in stmallist if len(mal) > 3]

    # Count and return the number of Indicator objects with proper and improper usage.
    return getMALinDesc(db, _stmallist), getValidMAL(db, _stmallist)
