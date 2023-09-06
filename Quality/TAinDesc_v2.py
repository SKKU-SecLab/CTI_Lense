import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json

def ValidTA(db, talist, mallist):
    col = "threat-actor"
    res = {}

    stixta = [d.lower() for d in db[col].distinct("name")]

    validTA = list(set(stixta) & set(talist))

    for ta in set(stixta) - set(talist):
        if ta.startswith("unc"):
            validTA.append(ta)
        elif ta.startswith("apt-c-"):
            validTA.append(ta)
        elif ta.startswith("magecart"):
            validTA.append(ta)

    return validTA

def getTAinDesc(dbdup, talist):
    col = "report"
    talist.remove("st")
    talist.remove("lead")

    query = {
        "description":{"$regex":"(?i)("+"|".join(talist)+")"}
    }
    TAinDes = dbdup[col].find(query)
    
    cnt = 0
    cnt_taobj = 0

    for rep in TAinDes:
        ck = 0
    
        for obj in rep["object_refs"]:
            if "threat-actor" in obj:
                ck = 1
                break
        for obj in rep["object_refs"]:
            if "indicator" in obj:
                if ck == 1:
                    cnt+=1
                    cnt_taobj+=1
                else:
                    cnt+=1

    return cnt - cnt_taobj

def getTAinDescSrc(dbdup, talist):
    col = "report"
    talist.remove("st")
    talist.remove("lead")
    
    srclist = dbdup[col].distinct("source")

    for src in srclist:
        print (src)
        query = {
            "description":{"$regex":"(?i)("+"|".join(talist)+")"},
            "source":src
        }
        TAinDes = dbdup[col].find(query)
    
        cnt = 0
        cnt_taobj = 0
        for rep in TAinDes:
            ck = 0
            for obj in rep["object_refs"]:
                if "threat-actor" in obj:
                    ck = 1
                    break
            for obj in rep["object_refs"]:
                if "indicator" in obj:
                    if ck == 1:
                        cnt+=1
                        cnt_taobj+=1
                    else:
                        cnt+=1

        print (cnt)
        print (cnt_taobj)

def getValidTAid(dbdup, talist):
    col = "threat-actor"
    
    query = {
        "name": {"$regex":"(?i)("+"|".join(talist)+")"}
    }

    validTAid = dbdup[col].distinct("_id", query)

    return list(validTAid)

def getIndc(db, validTAids):
    col = "indicator"

    query = {
        "taID":{"$in":validTAids}
    }

    validTA = db[col].count_documents(query)

    return validTA

def getIndcSrc(db, validTAids):
    col = "indicator"

    # validTAids = open("objids/validtaids_v2.txt").read().split("\n")[:-1]
    # taindescids = [int(i) for i in open("objids/taindesc.txt").read().split("\n")[:-1]]
    
    srclist = db[col].distinct("source")

    for src in srclist:
        print (src)
        query = {
            "taID":{"$in":validTAids},
            "source": src
        }

        validTA = db[col].count_documents(query)

        print (validTA)

if __name__ == "__main__":
    host = "localhost"
    port = 27017

    dbname = "STIX2"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    talist = open("dictionary/TAList.txt").read().split("\n")[:-1]

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
    validta = getValidTAid(db,validTA)
    
    print ("* Indicators representing threat actor")
    print ("Using description:", getTAinDesc(db, sttalist))
    print ("Using object/attribute:", getIndc(db, validta))

