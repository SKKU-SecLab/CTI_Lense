import os
import json

from bson import Code
from pymongo import MongoClient
from pymongo.database import Database

from multiprocessing import Pool
from collections import Counter


class rmDupObjv1:
    def __init__(self, host, port, db):
        self.rpath = "rmdata/"
        self.conn = MongoClient(host=host,port=port)
        self.db = self.conn[db]
        self.objs = Database(self.conn,db).list_collection_names()
        self.src = ["guest.MalwareDomainList_Hostlist",
                "guest.blutmagie_de_torExits", "guest.Lehigh_edu",
                "guest.CyberCrime_Tracker", "guest.EmergingThreats_rules",
                "guest.dataForLast_7daysOnly", "guest.Abuse_ch", "user_alienvault",
                "user_MALWAREPATROL", "user_JNAZARIO", "user_YARA_MATCHES",
                "user_JAMESBRINE", "user_BOTNETEXPOSER", "IBM X-Force"]
    
    def GetCollection(self, collection, query={}):
        return list(self.db[collection].find(query))

    def GetDup(self, objs, _key, ta=False, indc=False):
        stat = {}

        for obj in objs:
            if ta:
                key = obj[_key].lower() # escription"]
            elif indc:
                key = obj[_key]["idref"]
            else:
                key = obj[_key] # escription"]

            if key not in stat.keys():
                stat[key] = {
                    "cnt":0,
                    "timestamp":"",
                    "base_id":"",
                    "ids": []
                }
            stat[key]["cnt"]+=1
            stat[key]["ids"].append(obj["_id"])

            if stat[key]["base_id"] == "":
                stat[key]["base_id"] = obj["_id"]
            
            if "timestamp" in obj.keys():
                if stat[key]["timestamp"] == "":
                    stat[key]["timestamp"] = obj["timestamp"]

                else:
                    if stat[key]["timestamp"] > obj["timestamp"]:
                        stat[key]["timestamp"] = obj["timestamp"]
                        stat[key]["base_id"] = obj["_id"]

        return stat

    def COADup(self,obj="course_of_action",src=None):
        res = {}
        query = {}
        if src:
            query = {"source":src}
        coas = self.GetCollection(obj, query=query)
        stat = self.GetDup(coas,"description")

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]
            # break
        
        return res

    def ETDup(self,obj="exploit_target",src=None):
        res = {}
        query = {}
        if src:
            query = {"source":src}
        ets = self.GetCollection(obj, query=query)
        stat = self.GetDup(ets,"title")

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]
            # break
        
        return res
        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]
        
        return res

    def IncidDup(self, obj="incident",src=None):
        res = {}
        if src:
            query ={"description":{"$exists":True},"source":src}
        else:
            query ={"description":{"$exists":True}}

        
        incids = self.GetCollection(obj, query=query)
        stat = self.GetDup(incids,"description")

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]

        return res
        
    def TADup(self,obj="threat_actor",src=None):
        res = {}
        query = {}
        if src:
            query = {"source":src}

        tas = self.GetCollection(obj,query=query)
        stat = self.GetDup(tas,"title",ta=True)

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]
        
        return res

    def TTPDup(self,obj="ttp",src=None):
        res = {}
        if src:
            query = {"title":{"$exists":True},"source":src}
        else:
            query = {"title":{"$exists":True}} 

        ttps = self.GetCollection(obj, query=query)
        stat = self.GetDup(ttps,"title")

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]

        return res
        
    def IndcDup(self,obj="indicator",src=None):
        res = {}
        if src:
            query = {"observable.idref":{"$exists":True},"source":src}
        else:
            query = {"observable.idref":{"$exists":True}} 

        indcs = self.GetCollection(obj, query=query)
        stat = self.GetDup(indcs,"observable", indc=True)

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]

        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]

        return res

    def GetObsDup(self,objs):
        stat = {}

        for obj in objs:
            obtype = obj["object"]["properties"]["xsi:type"]
            if  obtype=="URIObjectType" or obtype=="DomainNameObjectType":
                if type(obj["object"]["properties"]["value"]) == type({}):
                    key = obj["object"]["properties"]["value"]["value"]
                else:
                    key = obj["object"]["properties"]["value"]
            elif obtype == "FileObjectType":
                if type(obj["object"]["properties"]["hashes"][0]["simple_hash_value"]) == type({}):
                    key = obj["object"]["properties"]["hashes"][0]["simple_hash_value"]["value"].lower()
                else:
                    key = obj["object"]["properties"]["hashes"][0]["simple_hash_value"].lower()
            elif obtype == "AddressObjectType":
                if type(obj["object"]["properties"]["address_value"]) == type({}):
                    if type(obj["object"]["properties"]["address_value"]["value"]) == type([]):
                        key = obj["object"]["properties"]["address_value"]["value"][0]+"/255"
                    else:
                        key = obj["object"]["properties"]["address_value"]["value"]
                else:
                    key = obj["object"]["properties"]["address_value"]
            elif obtype == "MutexObjectType":
                key = obj["object"]["properties"]["name"]

            else:
                continue

            # print (key)
            if key not in stat.keys():
                stat[key] = {
                    "cnt":0,
                    # "date":"2022-01-18",
                    "base_id":"",
                    "ids": []
                }
            stat[key]["cnt"]+=1
            stat[key]["ids"].append(obj["_id"])

            if stat[key]["base_id"] == "":
                stat[key]["base_id"] = obj["_id"]


            # if stat[key]["date"] > obj["date"]:
            #     stat[key]["date"] = obj["date"]
            #     stat[key]["base_id"] = obj["_id"]

        return stat
        # pass

    def ObsDup(self,obj="observable",src=None):
        res = {}
        Obstypes = self.db[obj].distinct("object.properties.xsi:type")

        if src:
            query = {"object":{"$exists":True},"source":src}
        else:
            query = {"object":{"$exists":True}}

        obs = self.GetCollection(obj, query=query)
        stat = self.GetObsDup(obs)

        dupdata = [value for key,value in stat.items() if value["cnt"] > 1]
        
        for dup in dupdata:
            dup["ids"].remove(dup["base_id"])
            res[dup["base_id"]] = dup["ids"]
            # break

        return res

    def SrcObjDup(self, obj=None):
        fmap = {
            "observable":"ObsDup",
            "course_of_action":"COADup",
            "incident":"IncidDup",
            "threat_actor":"TADup",
            "exploit_target":"ETDup",
            "indicator":"IndcDup",
            "ttp":"TTPDup"
        }
        res = {}
        for src in self.src:
            print (src)
            res[src] = eval("self."+fmap[obj]+"(src=src)")
        return res
        

    def rmObj(self, mapinfo):
        objs = mapinfo.keys()
        for obj in objs:
            for key in mapinfo[obj].keys():
                self.db[obj].delete_many({"_id":key})
        
    
    def updateObj(self,mapinfo):
        # target = {"indicator_types.value": "IP Watchlist"}
        # update = {"$set": {"indicator_types.$.value": "dasfdsfsfadsfasfd"}}
        # self.db["indicators"].update_many(target,update)
        
        for obj in self.objs:
            print (obj)
            for key, value in mapinfo[obj].items():
                if obj == "cource_of_action":
                    target = {"potential_coas.coas":key}
                    update = {"$set":{"potential_coas.coas.$":value}}
                    self.db["exploit_targets"].update_many(target,update)
                elif obj == "ttp":
                    # if key != "opensource:ttp-08b96668-60fe-4a85-b28e-31fc9fe917c2":
                    #     continue
                    target = {"indicated_ttps.ttp.idref":key}
                    update = {"$set":{"indicated_ttps.$.ttp.idref":value}}
                    self.db["indicators"].update_many(target,update)
                    # exit()
                elif obj == "observable":
                    target = {"observable.idref":key}
                    update = {"$set":{"observable.idref":value}}
                    self.db["indicators"].update_many(target,update)
                    target = {"observable_composition.observables.idref":key}
                    update = {"$set":{"observable_composition.observables.$.idref":value}}
                    self.db["observables"].update_many(target,update)

                elif obj == "incident":
                    target = {"incidID":key}
                    update = {"$set":{"incidID":value}}
                    self.db["indicators"].update_many(target,update)
                    self.db["observables"].update_many(target,update)
                    self.db["ttps"].update_many(target,update)
                    self.db["cource_of_actions"].update_many(target,update)
                    self.db["exploit_targets"].update_many(target,update)

                elif obj == "threat_actor":
                    target = {"taID":key}
                    update = {"$set":{"taID":value}}
                    self.db["indicators"].update_many(target,update)
                    self.db["observables"].update_many(target,update)
                    self.db["ttps"].update_many(target,update)
                    self.db["cource_of_actions"].update_many(target,update)
                    self.db["exploit_targets"].update_many(target,update)
                else:
                    continue




class rmDupObjv2:
    def __init__(self, host, port, db):
        self.conn = MongoClient(host=host,port=port)
        self.db = self.conn[db]
        self.objs = sorted(list(Database(self.conn,db).list_collection_names()))
        self.objkeys = {
            # "course-of-action":"name",
            "domain-name":"value",
            "indicator":"pattern",
            "malware":"name",
            # "observed-data":"object_refs",
            "relationship":"",
            "report":"object_refs",
            "sighting":"sighting_of_ref",
            "threat-actor":"name",
            "tool":"name",
            "url":"value",
            "vulnerability":"name",
            "location":"name",
            # "campaign":"name",
            # "intrusion-set":"name"
        }

    def GetCollection(self, collection, query={}):
        return list(self.db[collection].find(query))

    def GetDup(self, objs, _key, ta=False, indc=False):
        stat = {}

        for obj in objs:
            # print ()
            if obj["type"] == "malware" or obj["type"] == "threat-actor" or obj["type"] == "tool":
                key = obj[_key].lower()
            elif obj["type"] == "observed-data" or obj["type"] == "report":
                key = "|".join(obj[_key])
            elif obj["type"] == "relationship":
                key = obj["source_ref"]+obj["relationship_type"]+obj["target_ref"]
            else:
                key = obj[_key] # escription"]
            if key not in stat.keys():
                stat[key] = {
                    "cnt":0,
                    "date":"2023-05-18",
                    "base_id":"",
                    "flen":0,
                    "ids": []
                }
            stat[key]["cnt"]+=1
            stat[key]["ids"].append(obj["_id"])
            if "created" in obj.keys():
                if stat[key]["date"] >= obj["created"]:
                    stat[key]["date"] = obj["created"]
                    stat[key]["flen"] = len(obj.keys())
                    stat[key]["base_id"] = obj["_id"]
            
                if len(obj.keys()) > stat[key]["flen"]:
                    stat[key]["date"] = obj["created"]
                    stat[key]["flen"] = len(obj.keys())
                    stat[key]["base_id"] = obj["_id"]
            else:
                if len(obj.keys()) > stat[key]["flen"]:
                    # stat[key]["date"] = obj["created"]
                    stat[key]["flen"] = len(obj.keys())
                    stat[key]["base_id"] = obj["_id"]
        # print (stat)

        return stat

    def getObjDups(self):
        res = {}
        query = {}
    
        for obj in self.objs:
            print (obj)
            if obj not in res.keys():
                res[obj] = {}
            if obj not in self.objkeys.keys():
                continue
            objs = self.GetCollection(obj)
            stat = self.GetDup(objs, self.objkeys[obj])

            dupdata = [value for key,value in stat.items() if value["cnt"] > 1]
            
            for dup in dupdata:
                dup["ids"].remove(dup["base_id"])
                res[obj][dup["base_id"]] = dup["ids"]

        return res

    def rmObj(self, mapinfo):
        objs = mapinfo.keys()
        for obj in objs:
            print (obj)
            for key in mapinfo[obj].keys():
                self.db[obj].delete_many({"_id":key})        



