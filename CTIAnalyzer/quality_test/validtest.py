import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

from pymongo import MongoClient
from pymongo.database import Database

import json
import os

path = os.path.dirname(os.path.abspath(__file__))


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
        elif ta.startswith("ta"):
            validTA.append(ta)

        else:
            for _ta in talist:
                if _ta in ta:
                    validTA.append(ta)
                    break

    malwareTA = list((set(stixta) - set(validTA)) & set(mallist))
    unkownTA = list(set(stixta) - set(malwareTA) - set(validTA))
    
    res = {
        "Correct":len(validTA), 
        "Incorrect":len(malwareTA), 
        "Unmatched":len(unkownTA)
    }

    return res

def ValidSrcTA(db, talist, mallist):
    col = "threat_actor"
    res = {}
    
    stixsrc = db[col].distinct("source")
    
    for src in stixsrc:
        print (src)
        stixta = [d.lower() for d in db[col].distinct("title",{"source":src})]

        validTA = list(set(stixta) & set(talist))
    
        for ta in set(stixta) - set(talist):
            if ta.startswith("unc"):
                validTA.append(ta)
            elif ta.startswith("apt-c-"):
                validTA.append(ta)
            elif ta.startswith("magecart"):
                validTA.append(ta)
            elif ta.startswith("ta"):
                validTA.append(ta)

            else:
                for _ta in talist:
                    if _ta in ta:
                        validTA.append(ta)
                        break

        malwareTA = list((set(stixta) - set(validTA)) & set(mallist))
        unkownTA = list(set(stixta) - set(malwareTA) - set(validTA))

        print ("Valid TA obj:",len(validTA))
        print ("Malware in TA obj:", len(malwareTA))
        print ("Unknown TA obj:", len(unkownTA))


def ValidMAL(db, talist, mallist):
    col = "ttp"
    res = {}

    stixmal = [d.lower() for d in db[col].distinct("behavior.malware_instances.names")]

    validMAL = list(set(stixmal) & set(mallist))

    for mal in set(stixmal) - set(mallist):
        for _mal in mallist:
            if _mal in mal:
                validMAL.append(mal)
                break

    malwareMAL = list((set(stixmal) - set(validMAL)) & set(talist))
    unknownMAL = list(set(stixmal) - set(malwareMAL) - set(validMAL))

    res = {
        "Correct":len(validMAL), 
        "Incorrect":len(malwareMAL), 
        "Unmatched":len(unknownMAL)
    }

    return res 


def ValidSrcMAL(db, talist, mallist):
    col = "ttp"
    res = {}

    # stixmal = [d.lower() for d in db[col].distinct("behavior.malware_instances.names")]
    stix_src = db[col].distinct("source")
    
    for src in stix_src:
        print (src)
        stixmal = db[col].distinct("behavior.malware_instances.names",
                {"source":src})

        validMAL = list(set(stixmal) & set(mallist))

        for mal in set(stixmal) - set(mallist):
            for _mal in mallist:
                if _mal in mal:
                    validMAL.append(mal)
                    break
        # print (len(MALinDes2))


        malwareMAL = list((set(stixmal) - set(validMAL)) & set(talist))
        unknownMAL = list(set(stixmal) - set(malwareMAL) - set(validMAL))

        print ("Valid Malware obj:",len(validmal))
        print ("TA in TTP obj:", len(malwareMAL))
        print ("Unkown in TTP obj:", len(unknownMAL))


def run():
    host = "localhost"
    port = 27017

    dbname = "STIX1"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    talist = open(path+"/dictionary/TAList.txt").read().split("\n")[:-1]
    mallist = open(path+"/dictionary/MALlist.txt").read().split("\n")[:-1]

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

        if ta.endswith(" campaign"):
            sttalist.append(ta.replace(" campaign",""))
#             sttalist.append(ta.replace(" "," group"))    
    
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
    
    
    res = {}

    # print ("* Improper value")
    res["Threat actor (STIX 1)"] = ValidTA(db,sttalist,stmallist)
    res["TTP (STIX 1)"] = ValidMAL(db,sttalist,stmallist)

    return res

