import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json

# Function to retrieve Attack Patterns (AP) mentioned in the 'stix_header' collection based on a description query
def getAPinDesc(dbdup):
    col = "stix_header"

    # MongoDB query to find documents in 'stix_header' collection where description contains keywords related to attack patterns
    query = {
        "description":{"$regex":"(?i)(url|email|e-mail)"}
    }

    # Find distinct "_id" values that satisfy the query
    APinDes = dbdup[col].distinct("_id", query)

    return list(APinDes)

# Function to retrieve indicators with valid Attack Patterns
def getIndc(db, validTAids, taindescids):

    col = "indicator"

    # Define query for count the number of Indicator objects that contains attack pattern in stix_header description.
    query = {
        "hid":{"$in":taindescids}
    }

    taindesc = db[col].count_documents(query)

    # Define query for count the number of Indicator objects that contains attack pattern in valid object (TTP).
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
    
    # Count the number of common Incidator object between proper and improper usage
    common = db[col].count_documents(query)
    
    return taindesc,validTA-common

# Function to retrieve indicators with valid Attack Patterns for each source
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

def run():
    host = "localhost"
    port = 27017

    dbname = "STIX1"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    apindesc = getAPinDesc(db)
    validttp = ["opensource:ttp-c819f3ef-fbc3-4077-8d56-bf619c8d9b29"] 
    return getIndc(db, validttp, apindesc)






