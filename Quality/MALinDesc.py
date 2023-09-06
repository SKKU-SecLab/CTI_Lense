import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json

def ValidMAL(db, mallist):
    col = "ttp"
    res = {}

    stixmal = [d.lower() for d in db[col].distinct("behavior.malware_instances.names")]

    validMAL = list(set(stixmal) & set(mallist))

    for mal in set(stixmal) - set(mallist):
        for _mal in mallist:
            if _mal in mal:
                validMAL.append(mal)
                break

    return validMAL

def getMALinDesc(dbdup, mallist):
    col = "stix_header"
    lenlist = len(mallist)
    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[:int(lenlist/2)])+")"}
    }
    MALinDes1 = dbdup[col].distinct("_id", query)


    query = {
        "description":{"$regex":"(?i)("+"|".join(mallist[int(lenlist/2):])+")"}
    }
    MALinDes2 = dbdup[col].distinct("_id", query)

    return list(set(MALinDes1 + MALinDes2))

def getValidMALid(db, mallist):
    col = "ttp"
    
    query = {
        "behavior.malware_instances.names": {"$regex":"(?i)("+"|".join(mallist)+")"}
    }

    validMALid = list(db[col].distinct("_id", query))

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
    print ("* Indicators representing Malware category")
    print ("Using description:", taindesc)
    print ("Using object/attribute:", validTA - common)
#     print ("Common objects", common)
    # print (taindesc)
    # print (validTA)
    # print (common)

def getIndcSrc(db, validTAids, taindescids):
    col = "indicator"

    # validTAids = open("objids/validmalids.txt").read().split("\n")[:-1]
    # taindescids = [int(i) for i in open("objids/malindesc.txt").read().split("\n")[:-1]]
    
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



if __name__ == "__main__":
    host = "localhost"
    port = 27017

    dbname = "STIXv1_rmdup"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    mallist = open("dictionary/MALlist.txt").read().split("\n")[:-1]

    stmallist = []
    endwith_keyword = [" rat", " stealer", " ransom", " ransomware", " trojan",
                   " botnet", " pos", " downloader", " locker", " rootkit",
                   " worm", " logger", " keylogger", " clipper", " backdoor",
                   " webshell", " spy", " tds"]
    stawith_keyword = ["win.", "win32.", "win/", "win32/", "backdoor.",
                       "trojan.", "elf.", "android/", "mal/", "osx/",
                       "androidos/"]

    for mal in mallist:
        stmallist.append(mal)
        for key in endwith_keyword:
            if mal.endswith(key):
                stmallist.append(mal.replace(key,""))

        for key in stawith_keyword:
            if mal.startswith(key):
                stmallist.append(mal.replace(key,""))

    validMAL = ValidMAL(db,stmallist)
    # print (validMAL)

    stmallist = list(set(stmallist))

    for stmal in stmallist:
        if len(stmal) < 5:
            stmallist.remove(stmal)


    malindesc = getMALinDesc(db, stmallist)
    validttp = getValidMALid(db,validMAL)
    getIndc(db, validttp, malindesc)






