import os
import json
import re
from bson import Code
from pymongo import MongoClient
from pymongo.database import Database

from multiprocessing import Pool
from collections import Counter

import datetime
import dateutil.parser
import pytz
import time
import math

# Define a class for interacting with a MongoDB database for STIX 1 data.
class DBMv1:
    def __init__(self, host, port, db, path):
        # Load core object attribute information from a JSON file
        self.core_obj_attr = json.loads(open(path+"/data/STIXv1_obj_attr_info.json").read())
        # Define a list of object types
        self.objs = ['campaign', 'course_of_action', 'exploit_target','incident', 'indicator', 'threat_actor','ttp', 'report']
        self.conn = MongoClient(host=host,port=port)
        self.db = self.conn[db]
        # Define a list of data sources
        self.src = ["AlienVault","HailaTAXII","IBMxForce_pub","PickupTAXII"]

    # Function to retrieve documents from a specified collection based on a query
    def GetCollection(self, collection, query={}):
        return list(self.db[collection].find(query))
    
    # Function to count the number of documents for each object type
    def ObjCnt(self):
        return dict([(obj,self.db[obj].count_documents({})) for obj in self.objs])

    # Function to calculate object attribute coverage for each object type
    def ObjAttrCov(self):
        res = {}
        for obj, attrs in self.core_obj_attr.items():
            cov = 0
            for attr in attrs:
                # Check if the attribute exists in any document of the object type
                if self.db[obj].find_one({attr:{"$exists":True}}):
                    cov += 1
            res[obj] = (cov,len(attrs))
        return res  

    # Function to count the occurrences of object attributes for each object type
    def ObjAttrCnt(self,obj=None):
        if obj:
            res = dict([(attr,0) for attr in self.core_obj_attr[obj]])
            data = self.GetCollection(obj)
            for d in data:
                for key in d.keys():
                    if key in self.core_obj_attr[obj]:
                        res[key] += 1

            return dict(sorted([(k,v) for k,v in res.items()], key = lambda x: x[1], reverse=True))

        res = dict([(obj,{}) for obj in self.objs])

        for obj,value in res.items():
            data = self.GetCollection(obj)
            for d in data:
                for key in d.keys():
                    if key not in res[obj].keys():
                        res[obj][key] = 0
                    res[obj][key] += 1
        
        return res 

    # Function to count the number of documents for each object type and data source
    def SrcObjCnt(self):
        res = dict([(source,{}) for source in self.src]) 
        for source in self.src:
            for obj in self.objs:
                res[source][obj] = self.db[obj].count_documents({"source":source})

        return res

    # Function to count the occurrences of object attributes for each object type and data source
    def SrcObjAttrCnt(self):
        res = dict([(source,{}) for source in self.src]) 
        for source in self.src:
            for obj in self.objs:
                res[source][obj] = {} 
        
        for obj in self.objs:
            data = self.GetCollection(obj)
            for d in data:
                for key in d.keys():
                    if key not in res[d["source"]][obj].keys():
                        res[d["source"]][obj][key] = 0
                    res[d["source"]][obj][key] += 1

        return res

    # Function to count the number of documents of a specified object type based on a query
    def ObsType(self,query):
        return self.db[obj].count_documents(query)

    # Function to count the occurrences of observable types for each data source (or globally) for a specified object type
    def ObsTypeCnt(self,src=None,obj="observables"):
        obstypes = self.db[obj].distinct("object.properties.xsi:type")

        if src:
            return dict([(obstype,self.db[obj].count_documents({"object.properties.xsi:type":obstype, "source":src})) for obstype in obstypes])

        return dict([(obstype,self.db[obj].count_documents({"object.properties.xsi:type":obstype})) for obstype in obstypes])

        
class DBMv2:
    def __init__(self, host, port, db, path):
        self.conn = MongoClient(host=host,port=port)
        self.db = self.conn[db]
        # Load core object attribute information from a JSON file
        self.core_obj_attr = json.loads(open(path+"/data/STIXv2_obj_attr_info.json").read())
        # Define a list of object types in STIX version 2
        self.objs = ["attack-pattern", "campaign", "course-of-action", "grouping",
                "identity", "indicator", "infrastructure", "intrusion-set", "location", 
                "malware", "malware-analysis", "note", "observed-data", "opinion",  
                "report", "threat-actor", "tool","vulnerability","relationship", "sighting"]
        # Define a list of data sources
        self.src = ["AlienVault","JamesBrine", "DigitalSide", "Cyware",
                "IBMxForce_pub", "Unit42", "MitreAttack","LimoAnomali","PickupSTIX"]
 
    # Function to retrieve documents from a specified collection based on a query    
    def GetCollection(self, collection, query={}):
        return self.db[collection].find(query)

    # Function to count the number of documents for each object type
    def ObjCnt(self):
        return dict([(obj,self.db[obj].count_documents({})) for obj in self.objs])

    # Function to calculate object attribute coverage for each object type
    def ObjAttrCov(self):
        res = {}
        for obj, attrs in self.core_obj_attr.items():
            cov = 0
            for attr in attrs:
                if self.db[obj].find_one({attr:{"$exists":True}}):
                    cov += 1
            res[obj] = (cov,len(attrs))
        return res

    # Function to count the occurrences of object attributes for each object type
    def ObjAttrCnt(self, obj=None):
        if obj:
            res = dict([(attr,0) for attr in self.core_obj_attr[obj]])
            data = self.GetCollection(obj)
            for d in data:
                for key in d.keys():
                    if key in self.core_obj_attr[obj]:
                        res[key] += 1

            return dict(sorted([(k,v) for k,v in res.items()], key = lambda x: x[1], reverse=True))

        res = dict([(obj,{}) for obj in self.objs])
        for obj,value in res.items():
            data = self.GetCollection(obj)
            for d in data:
                for key in d.keys():
                    if key not in res[obj].keys():
                        res[obj][key] = 0
                    res[obj][key] += 1 
        return res

    # Function to count the number of documents for each object type and data source
    def SrcObjCnt(self):
        res = dict([(source,{}) for source in self.src]) 
        for source in self.src:
            for obj in self.objs:
                res[source][obj] = self.db[obj].count_documents({"source":source})

        return res

    # Function to count the total number of documents for each data source
    def SrcCnt(self):
        res = dict([(source,0) for source in self.src]) 
        for source in self.src:
            for obj in self.objs:
                res[source] += self.db[obj].count_documents({"source":source})

        return res    

    # Function to count the occurrences of object attributes for each object type and data source
    def SrcObjAttrCnt(self):
        res = dict([(source,{}) for source in self.src]) 
        for source in self.src:
            for obj in self.objs:
                res[source][obj] = {} 
        
        for obj in self.objs:
            data = self.GetCollection(obj)
            for d in data:
                for key in d.keys():
                    if key not in res[d["source"]][obj].keys():
                        res[d["source"]][obj][key] = 0
                    res[d["source"]][obj][key] += 1

        return res




