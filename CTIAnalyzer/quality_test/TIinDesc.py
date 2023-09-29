import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json

def ValidMAL(db):
    col = "ttp"
    res = {}

    stixmal = [d.lower() for d in db[col].distinct("victim_targeting.identity.name")]

    return list(stixmal)

def getAPinDesc(db):
    col = "stix_header"

    mallist = ValidMAL(db)

    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist)+")"}
    }
    APinDes = db[col].distinct("_id", query)


    return list(APinDes)

def getValidMALid(db):
    col = "ttp"
    
    mallist = ValidMAL(db)

    query = {
        "victim_targeting.identity.name": {"$regex":"(?i)("+"|".join(mallist)+")"}
    }

    validMALid = list(db[col].distinct("_id", query))

    # print (validMALid)
    return validMALid

def getIndc(db, validTAids, taindescids):
    col = "indicator"

    query = {
        "hid":{"$in":taindescids}
    }

    taindesc = db[col].count_documents(query)

    query = {
        "indicated_ttps.ttp.idref":{"$in":validTAids}
    }

    validTA = db[col].count_documents(query)

    query = {
        "$and":[
            {"hid":{"$in":taindescids}},
            {"indicated_ttps.ttp.idref":{"$in":validTAids}}
        ]
    }

    common = db[col].count_documents(query)

#     print ("* Indicators representing target information")
#     print ("Using description:", taindesc)
#     print ("Using object/attribute:", validTA - common)

    return taindesc, validTA-common

def getIndcSrc(db, validTAids, taindescids):
    col = "indicator"

    srclist = db[col].distinct("source")
    for src in srclist:
        print (src)
        query = {
            "hid":{"$in":taindescids},
            "source":src
        }

        taindesc = db[col].count_documents(query)

        query = {
            "indicated_ttps.ttp.idref":{"$in":validTAids},
            "source":src
        }

        validTA = db[col].count_documents(query)
    
        query = {
            "$and":[
                {"hid":{"$in":taindescids}},
                {"indicated_ttps.ttp.idref":{"$in":validTAids}},
                {"source":src}
            ]
        }

        common = db[col].count_documents(query)

        print ("* Indicators representing target information")
        print ("Using description:", taindesc)
        print ("Using object/attribute", validTA)
        print ("Common objects", common)


def run():
    host = "localhost"
    port = 27017

    dbname = "STIX1"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    apindesc = getAPinDesc(db)
    validttp = getValidMALid(db)
    return getIndc(db, validttp, apindesc)






