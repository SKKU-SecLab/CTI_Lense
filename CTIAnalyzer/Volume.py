import sys
sys.path.append('..') 

from pymongo import MongoClient
from pymongo.database import Database

from DataManager.DBMange import *
import json
import os

path = os.path.dirname(os.path.abspath(__file__))

def pprint(_json):
    print(json.dumps(_json, indent=4, separators=(",", ":")))

# Function to display the volume of unique data for each STIX source in a tabular format
def table1_volume_source():
    
    # MongoDB connection parameters
    host = "localhost"
    port = 27017
    
    # Connect to the MongoDB server
    conn = MongoClient(host=host, port=port)

    # Specify the names of the MongoDB databases for STIX1 and STIX2
    dbname1 = "STIX1"
    dbname2 = "STIX2"

    # Create instances of custom DBMv1 and DBMv2 classes for managing the databases
    dbmv1 = DBMv1(host, port, dbname1, path)
    dbmv2 = DBMv2(host, port, dbname2, path)
    
    # Print the volume of unique data for each STIX source in a tabular format
    print("* Table I - Volume of unique data for each STIX source")
    print("=" * 25)
    print("{:<15}{:>9}".format("STIX sources", "Unique"))
    print("-" * 25)
    
    # STIX 1 Database
    print("STIX 1")
    for key, value in dbmv1.SrcObjCnt().items():
        _sum = "{:,}".format(sum([v for k, v in value.items()]))
        print("{:<15}{:>10}".format(key, _sum))

    print("-" * 25)

    # STIX 2 Database
    print("STIX 2")
    for key, value in dbmv2.SrcObjCnt().items():
        _sum = "{:,}".format(sum([v for k, v in value.items()]))
        print("{:<15}{:>10}".format(key, _sum))
    print("-" * 25)
