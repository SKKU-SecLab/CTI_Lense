import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json

# Function to retrieve the number of unique indicators related to Attack pattern based on a list of attack pattern related keywords in the description
def getMALinDesc(dbdup, mallist):
    col = "report"
    lenlist = len(mallist)

    # MongoDB query to find reports where the description contains keywords related to attack pattern (first half of the list)
    res = []
    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"}
    }

    MALinDes1 = list(dbdup[col].find(query))
    
    cnt = 0
    for rep in MALinDes1:
        for obj in rep["object_refs"]:
            if "indicator" in obj:
                res.append(obj)
    
    # MongoDB query to find reports where the description contains keywords related to attack pattern (second half of the list)
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
    
    srclist = dbdup[col].distinct("source")

    for src in srclist:
        res = []
        print (src)
        query = {
            "description":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"},
            "source":src
        }

        MALinDes1 = list(dbdup[col].find(query))
    
        cnt = 0
        for rep in MALinDes1:
            for obj in rep["object_refs"]:
                if "indicator" in obj:
                    res.append(obj)
#                 cnt+=1

        query = {
            "description":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"},
            "source":src
        }

        MALinDes2 = list(dbdup[col].find(query))

        for rep in MALinDes2:
            for obj in rep["object_refs"]:
                if "indicator" in obj:
                    res.append(obj)
#                 cnt+=1

    
        print (len(set(res)))


def getValidMALSrc(db, mallist):
    col = "indicator"
    # print ("valid test")
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

def getValidMAL(db, mallist):
    col = "indicator"
    lenlist = len(mallist)
    cnt = 0
    res = []

    # MongoDB query to find valid indicators where the labels contain keywords related to malware 
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


def run():
    host = "localhost"
    port = 27017

    dbname = "STIX2"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]
    
    # list of keywords related to the Attack pattern
    stmallist = ["bruteforce","phishing","delivery_email", "email", "delivery","brute-force", "brute force","Category : Brute Force Blocker", "Brute Force Login Attack","scanning_host"]

    return getMALinDesc(db, stmallist), getValidMAL(db, stmallist)


