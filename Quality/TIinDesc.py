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

def getAPinDesc(dbdup):
    col = "stix_header"

    mallist = ValidMAL(db)

    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist)+")"}
    }
    APinDes = dbdup[col].distinct("_id", query)


    return list(APinDes)

def getValidMALid(db):
    col = "ttp"
    
    mallist = ValidMAL(db)

    query = {
        "victim_targeting.identity.name": {"$regex":"(?i)("+"|".join(mallist)+")"}
    }

    validMALid = list(dbdup[col].distinct("_id", query))

    # print (validMALid)
    return validMALid

def getIndc(db, validTAids, taindescids):
    col = "indicator"

    # validTAids = open("objids/validmalids.txt").read().split("\n")[:-1]
    # taindescids = [int(i) for i in open("objids/malindesc.txt").read().split("\n")[:-1]]
    
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

    print ("* Indicators representing target information")
    print ("Using description:", taindesc)
    print ("Using object/attribute:", validTA - common)
#     print ("Common objects", common)

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


if __name__ == "__main__":
    host = "localhost"
    port = 27017

    dbname = "STIXv1_rmdup"
    dbnamedup = "STIXv1"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]
    dbdup = conn[dbnamedup]


    # print ()

    apindesc = getAPinDesc(dbdup)
    validttp = getValidMALid(dbdup)
    getIndc(db, validttp, apindesc)






