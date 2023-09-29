import json
import os

from DataManager import SaveSTIXv1
from DataManager import SaveSTIXv2

from pymongo import MongoClient
from pymongo.database import Database
from stix.core import STIXPackage

from argparse import ArgumentParser


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-ov1", type=str, help="Input directory for STIX1 file", dest="opath1")
    parser.add_argument("-ov2", type=str, help="Input directory for STIX2 file", dest="opath2")
    args = parser.parse_args()
    
    opath1 = None
    opath2 = None

    if args.opath1:
        opath1 = args.opath1

    if args.opath2:
        opath2 = args.opath2

    host = "localhost"
    port = 27017
    dbname1 = "STIX1_test"
    dbname2 = "STIX2"

    conn = MongoClient(host=host,port=port)
    db1 = conn[dbname1]
    db2 = conn[dbname2]
    
    if opath1:
        SaveSTIXv1.SaveAll(db1, opath1)

    if opath2:
        SaveSTIXv2.SaveAll(db2, opath2)

