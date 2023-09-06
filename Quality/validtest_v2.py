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
        elif ta.startswith("ta"):
            validTA.append(ta)
        else:
            for _ta in talist:
                if _ta in ta:
                    validTA.append(ta)
                    break

    malwareTA = list((set(stixta) - set(validTA)) & set(mallist))
    unkownTA = list(set(stixta) - set(malwareTA) - set(validTA))

    print ("Valid threat actor object value:",len(validTA))
    print ("Malware in threat actor object value :", len(malwareTA))
    print ("Unmatched threat actor obj:", len(unkownTA))

    # for ta in sorted(unkownTA):
    #     print (ta)

def ValidMAL(db, talist, mallist):
    col = "malware"
    res = {}

    stixmal = [d.lower() for d in db[col].distinct("name")]

    validMAL = list(set(stixmal) & set(mallist))

    for mal in set(stixmal) - set(mallist):
        for _mal in mallist:
            if _mal in mal:
                validMAL.append(mal)
                break

    malwareMAL = list((set(stixmal) - set(validMAL)) & set(talist))
    unknownMAL = list(set(stixmal) - set(malwareMAL) - set(validMAL))

    print ("Valid Malware object value:",len(validMAL))
    print ("Threat actor in Malware object value :", len(malwareMAL))
    print ("Unmatched Malware obj:", len(unknownMAL))


def ValidTASrc(db, talist, mallist):
    col = "threat-actor"
    res = {}
    
    stixsrc = db[col].distinct("source")
    for src in stixsrc:
        print (src)
        stixta = [d.lower() for d in db[col].distinct("name", {"source":src})]

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

    # for ta in sorted(unkownTA):
    #     print (ta)

def ValidMALSrc(db, talist, mallist):
    col = "malware"
    res = {}

    stixsrc = db[col].distinct("source")
    for src in stixsrc:
        print (src)
        stixmal = [d.lower() for d in db[col].distinct("name",{"source":src})]

        validMAL = list(set(stixmal) & set(mallist))

        for mal in set(stixmal) - set(mallist):
            for _mal in mallist:
                if _mal in mal:
                    validMAL.append(mal)
                    break

        malwareMAL = list((set(stixmal) - set(validMAL)) & set(talist))
        unknownMAL = list(set(stixmal) - set(malwareMAL) - set(validMAL))

        print ("Valid Malware obj:",len(validMAL))
        print ("TA in TTP obj:", len(malwareMAL))
        print ("Unkown in TTP obj:", len(unknownMAL))

    # print (unknownMAL)

if __name__ == "__main__":
    host = "localhost"
    port = 27017

    dbname = "STIX2"

    conn = MongoClient(host=host,port=port)
    db = conn[dbname]

    talist = open("dictionary/TAList.txt").read().split("\n")[:-1]
    mallist = open("dictionary/MALlist.txt").read().split("\n")[:-1]

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


    print ("STIX2 - Threat actor")
    ValidTA(db,sttalist,stmallist)
    print ("\nSTIX2 - Malware")
    ValidMAL(db,sttalist,stmallist)

