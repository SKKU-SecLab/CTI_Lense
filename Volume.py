from pymongo import MongoClient
from pymongo.database import Database

from DataManager.DBMange import *
import json

def pprint (_json):
    print (json.dumps(_json, indent=4, separators=(",",":")))

if __name__ == "__main__":
    
    host = "localhost"
    port = 27017
    conn = MongoClient(host=host,port=port)

    dbname1 = "STIX1"
    dbname2 = "STIX2"

    dbmv1 = DBMv1(host, port, dbname1)
    dbmv2 = DBMv2(host, port, dbname2)
    
    # Volmue
    print ("* Volume of unique data for each STIX sources\n")
    print ("STIX 1")
    for key,value in dbmv1.SrcObjCnt().items():
        print (key+":", sum([v for k,v in value.items()]))
    
    print ("\nSTIX 2")
    for key,value in dbmv2.SrcObjCnt().items():
        print (key+":", sum([v for k,v in value.items()]))

