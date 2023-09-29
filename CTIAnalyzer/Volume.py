import sys
sys.path.append('..')

from pymongo import MongoClient
from pymongo.database import Database

from DataManager.DBMange import *
import json
import os

path = os.path.dirname(os.path.abspath(__file__))


def pprint (_json):
    print (json.dumps(_json, indent=4, separators=(",",":")))

def table1_volume_source():
    
    host = "localhost"
    port = 27017
    conn = MongoClient(host=host,port=port)

    dbname1 = "STIX1"
    dbname2 = "STIX2"

    dbmv1 = DBMv1(host, port, dbname1, path)
    dbmv2 = DBMv2(host, port, dbname2, path)
    
    # Volmue
    print ("* Table I - Volume of unique data for each STIX sources")
    print ("="*25)
    print ("{:<15}{:>9}".format("STIX sources", "Unique"))
    print ("-"*25)
    
    print ("STIX 1")
    for key,value in dbmv1.SrcObjCnt().items():
        _sum = "{:,}".format(sum([v for k,v in value.items()]))
        print ("{:<15}{:>10}".format(key, _sum))

    print ("-"*25)

    print ("STIX 2")
    for key,value in dbmv2.SrcObjCnt().items():
        _sum = "{:,}".format(sum([v for k,v in value.items()]))
        print ("{:<15}{:>10}".format(key, _sum))
    print ("-"*25)

