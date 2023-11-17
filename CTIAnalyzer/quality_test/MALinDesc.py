import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json
import os

path = os.path.dirname(os.path.abspath(__file__))

# Function to identify valid Malware based on a list of malware-related keywords
def ValidMAL(db, mallist):
    col = "ttp"
    res = {}

    # Get distinct malware names from the 'behavior.malware_instances.names' field in the 'ttp' collection
    stixmal = [d.lower() for d in db[col].distinct("behavior.malware_instances.names")]

    # Find the intersection of StixMal and Mallist to get valid malware
    validMAL = list(set(stixmal) & set(mallist))

    # Iterate through StixMal and Mallist to find additional valid malware
    for mal in set(stixmal) - set(mallist):
        for _mal in mallist:
            if _mal in mal:
                validMAL.append(mal)
                break

    return validMAL

# Function to retrieve Malware instances in TTP objects mentioned in the 'stix_header' collection based on a description query
def getMALinDesc(dbdup, mallist):
    col = "stix_header"
    lenlist = len(mallist)

    # MongoDB query to find documents in the 'stix_header' collection where the description contains keywords related to malware
    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"}
    }
    MALinDes1 = dbdup[col].distinct("_id", query)


    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"}
    }
    MALinDes2 = dbdup[col].distinct("_id", query)

    return list(set(MALinDes1 + MALinDes2))

# Function to get valid Malware IDs based on a list of malware-related keywords
def getValidMALid(db, mallist):
    col = "ttp"
    
    # Query to get the TTP ID with valid keywords
    query = {
        "behavior.malware_instances.names": {"$regex":"(?i)("+"|".join(mallist)+")"}
    }

    validMALid = list(db[col].distinct("_id", query))

    return validMALid

# Function to get indicators and their counts based on valid Malware indicator IDs
def getIndc(db, validTAids, taindescids):
    col = "indicator"
    
    # Query for counting the number of Inidcator objects with Malware instance information in invalid object with description in stix_header object.
    query = {
        "hid":{"$in":taindescids}
    }

    taindesc = db[col].count_documents(query)

    # Query for counting the number of Inidcator objects with Malware instance information in valid object with TTP objects.
    query = {
        "indicated_ttps.ttp.idref":{"$in":validTAids}
    }

    validTA = db[col].count_documents(query)
    
    # Query for counting the number of common objects
    query = {
        "$and":[
            {"hid":{"$in":taindescids}},
            {"indicated_ttps.ttp.idref":{"$in":validTAids}}
        ]
    }

    common = db[col].count_documents(query)

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
        
        print ("* Indicators representing Malware category")
        print ("Using description:", taindesc)
        print ("Using object/attribute", validTA)
        print ("Common objects", common)



def run():
    host = "localhost"
    port = 27017

    dbname = "STIXv1_rmdup"

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

    validMAL = ValidMAL(db,stmallist)

    stmallist = list(set(stmallist))

    for stmal in stmallist:
        if len(stmal) < 5:
            stmallist.remove(stmal)

    # Count the number of Indicator objects with proper and improper usage.
    malindesc = getMALinDesc(db, stmallist)
    validttp = getValidMALid(db,validMAL)
    return getIndc(db, validttp, malindesc)

