import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json

def getAPinDesc(dbdup):
    col = "stix_header"

    query = {
        "description":{"$regex":"(?i)(url|email|e-mail)"}
    }
    APinDes = dbdup[col].distinct("_id", query)


    return list(APinDes)

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
    
    print ("* Indicators representing attack pattern")
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

        print ("* Indicators representing attack pattern")
        print ("Using description:", taindesc)
        print ("Using object/attribute", validTA)
        print ("Common objects", common)

if __name__ == "__main__":
    host = "localhost"
    port = 27017

    dbname = "STIX1"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    apindesc = getAPinDesc(db)
    validttp = ["opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"] 
    getIndc(db, validttp, apindesc)






