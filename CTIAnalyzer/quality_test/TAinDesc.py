import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json
import os

path = os.path.dirname(os.path.abspath(__file__))

# Function to identify valid Threat actor based on a list of threat actor related keywords
def ValidTA(db, talist, mallist):
    col = "threat_actor"
    res = {}

    stixta = [d.lower() for d in db[col].distinct("title")]

    validTA = list(set(stixta) & set(talist))

    for ta in set(stixta) - set(talist):
        if ta.startswith("unc"):
            validTA.append(ta)
        elif ta.startswith("apt-c-"):
            validTA.append(ta)
        elif ta.startswith("magecart"):
            validTA.append(ta)

    return validTA

# Function to retrieve Threat actor mentioned in the 'stix_header' collection based on a description query
def getTAinDesc(dbdup, talist):
    col = "stix_header"
    # remove remaining invalid keywords
    talist.remove("st")
    talist.remove("lead")

    # MongoDB query to find documents in the 'stix_header' collection where the description contains keywords related to threat actor
    query = {
        "title":{"$regex":"(?i)("+"|".join(talist)+")"}
    }
    TAinDes = dbdup[col].distinct("_id", query)
    
    for ta in TAinDes:
        print (ta)


def getValidTAid(db, talist):
    col = "threat_actor"
    
    query = {
        "title": {"$regex":"(?i)("+"|".join(talist)+")"}
    }

    validTAid = dbdup[col].distinct("_id", query)

    for val in validTAid:
        print (val)

def getIndc(db):
    col = "indicator"
    
    # Get Valid TA list
    validTAids = open(path+"/objids/validtaids_2.txt").read().split("\n")[:-1]
    taindescids = [int(i) for i in open(path+"/objids/taindesc_2.txt").read().split("\n")[:-1]]
    
    # Query for counting the number of Inidcator objects with Threat actor information in invalid object with description in stix_header object.
    query = {
        "hid":{"$in":taindescids}
    }

    taindesc = db[col].count_documents(query)
    
    # Query for counting the number of Inidcator objects with Threat actor information in valid object with TTP objects.
    query = {
        "taID":{"$in":validTAids}
    }

    validTA = db[col].count_documents(query)

    # Query for counting the number of common objects
    query = {
        "$and":[
            {"hid":{"$in":taindescids}},
            {"taID":{"$in":validTAids}}
        ]
    }

    common = db[col].count_documents(query)

    return taindesc, validTA - common


def getIndcSrc(db):
    col = "indicator"

    validTAids = open("objids/validtaids_2.txt").read().split("\n")[:-1]
    taindescids = [int(i) for i in open("objids/taindesc_2.txt").read().split("\n")[:-1]]
    
    srclist = db[col].distinct("source")

    for src in srclist:
        print (src)
        query = {
            "hid":{"$in":taindescids},
            "source":src
        }

        taindesc = db[col].count_documents(query)

        query = {
            "taID":{"$in":validTAids},
            "source":src
        }

        validTA = db[col].count_documents(query)

        query = {
            "$and":[
                {"hid":{"$in":taindescids}},
                {"taID":{"$in":validTAids}},
                {"source":src}
            ]
        }

        common = db[col].count_documents(query)

        print ("* Indicators representing threat actor")
        print ("Using description:", taindesc)
        print ("Using object/attribute", validTA)
        print ("Common objects", common)

def run():
    host = "localhost"
    port = 27017

    dbname = "STIX1"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    talist = open(path+"/dictionary/TAList.txt").read().split("\n")[:-1]

    sttalist  = []

    for ta in talist:
        sttalist.append(ta)
        if " " in ta:
            sttalist.append(ta.replace(" ",""))

        if ta.startswith("apt"):
            sttalist.append(ta.replace("apt","apt "))

        if ta.endswith(" group"):
            sttalist.append(ta.replace(" group",""))
            sttalist.append(ta.replace(" group"," team"))

        if ta.endswith(" team"):
            sttalist.append(ta.replace(" team",""))
            sttalist.append(ta.replace(" team"," group"))

    validTA = ValidTA(db,sttalist,[])

    sttalist = list(set(sttalist))

    return getIndc(db)






