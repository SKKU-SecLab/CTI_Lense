import sys
sys.path.append('..')
import os

from pymongo import MongoClient
from pymongo.database import Database

from DataManager.DBMange import *
import json

path = os.path.dirname(os.path.abspath(__file__))

def pprint (_json):
    print (json.dumps(_json, indent=4, separators=(",",":")))


class Diversity:

    def __init__(self):
        host = "localhost"
        port = 27017
        dbname1 = "STIX1"
        dbname2 = "STIX2"
        conn = MongoClient(host=host,port=port)

        self.dbmv1 = DBMv1(host, port, dbname1, path)
        self.dbmv2 = DBMv2(host, port, dbname2, path)    

    def table3_ObjAttrCoverage(self):

        # Volmue
        print ("* Table III - Objects and attributes used in STIX dataset")
        print ("="*52)
        print ("{:<18}  {:^18}{:^14}".format("STIX version", "Objects", "Attributes"))
        print ("-"*52)
        print ("{:<18}{:>10}{:>8}{:>8}{:>8}".format("STIX 1", "Count", "Prop.", "Usage", "Prop."))
        print ("-"*52)
    
        data = self.dbmv1.ObjCnt()
        data_attr = self.dbmv1.ObjAttrCov()
        total = sum([v for k,v in data.items()])

        for key,value in data.items():
            source = key
            objcnt = "{:,}".format(value)
            objprop = "{:.2%}".format(value/total)
            attrusage = "{}/{}".format(data_attr[key][0], data_attr[key][1])
            attrprop = "{:.2%}".format(data_attr[key][0]/data_attr[key][1])
            print ("{:<18}{:>10}{:>8}{:>8}{:>8}".format(source, objcnt, objprop, attrusage, attrprop))
        print ("-"*52)
        print ("{:<18}{:>10}{:>8}{:>8}{:>8}".format("STIX 2", "Count", "Prop.", "Usage", "Prop."))
        print ("-"*52)

        data = self.dbmv2.ObjCnt()
        data_attr = self.dbmv2.ObjAttrCov()
        total = sum([v for k,v in data.items()])

        for key,value in data.items():
            source = key
            objcnt = "{:,}".format(value)
            objprop = "{:.2%}".format(value/total)
            attrusage = "{}/{}".format(data_attr[key][0], data_attr[key][1])
            attrprop = "{:.2%}".format(data_attr[key][0]/data_attr[key][1])
            print ("{:<18}{:>10}{:>8}{:>8}{:>8}".format(source, objcnt, objprop, attrusage, attrprop))
        print ("="*52)


    def table6_IndicatorAttrCoverage(self, obj="indicator"):


        print ("* Table VI - Attributes used in Indicator objects")
        print ("="*54)
        print ("{:<14}{:<20}{:>10}{:>10}".format("STIX version", "Attributes", "Count", "Prop."))
        print ("-"*54)
        objcnt = self.dbmv1.ObjCnt()
        objattrcnt = self.dbmv1.ObjAttrCnt(obj=obj)
        ck = 1
        for k,v in objattrcnt.items():
            if v == 0:
                continue
            attr = k
            cnt = "{:,}".format(v)
            prop = "{:.2%}".format(v/objcnt[obj])

            if ck:
                print ("{:<14}{:<20}{:>10}{:>10}".format("STIX 1", attr, cnt, prop))
                ck = 0
                continue

            print ("{:<14}{:<20}{:>10}{:>10}".format("", attr, cnt, prop))
       
        print ("-"*54)
        objcnt = self.dbmv2.ObjCnt()
        objattrcnt = self.dbmv2.ObjAttrCnt(obj=obj)
        ck = 1
        for k,v in objattrcnt.items():
            if v == 0:
                continue
            attr = k
            cnt = "{:,}".format(v)
            prop = "{:.2%}".format(v/objcnt[obj])

            if ck:
                print ("{:<14}{:<20}{:>10}{:>10}".format("STIX 1", attr, cnt, prop))
                ck = 0
                continue

            print ("{:<14}{:<20}{:>10}{:>10}".format("", attr, cnt, prop))
       
        print ("-"*54)

