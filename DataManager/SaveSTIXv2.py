import os, fnmatch
import json

from pymongo import MongoClient
from pprint import pprint
from stix.core import STIXPackage
from pymongo.errors import DuplicateKeyError

def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename

def find_all_files(path):
    res = []
    for filename in find_files(path,"*.json"):
        res.append(filename)

    return res


def SaveObj(db,Objlist,source,taID,incidID):
    # collection = db["indicators"]
    for obj in Objlist:
        collection = db[obj["type"]]
        _obj = dict(obj)
        _obj["_id"] = _obj.pop("id")
        _obj["taID"] = taID
        _obj["incidID"] = incidID
        _obj["source"] = source
        # print (json.dumps(_obj, indent=4, separators=(",",":")))
        
        try:
            collection.insert_one(_obj)
        except DuplicateKeyError:
            pass
        except:
            with open("error_save_obj.log","a") as wf:
                wf.write("STIXv2_"+ source+"_"+_obj["_id"]+"\n")
        

def SaveAll(db, path):
    flist =  sorted(find_all_files(path))
    taID = ""
    IncidID = ""

    for f in flist:

        source = f.split("/")[2]

        try:
            data = json.loads(open(f).read())
            # print (data)
        except:
            with open("save_error_v2.log","a") as wf:
                wf.write(f+"\n")
            continue
        
        if type(data) != type({}):
            continue

        if "objects" not in data.keys():
            with open("save_error_v2.log","a") as wf:
                wf.write(f+"\n")
            continue

        for obj in data["objects"]:
            if obj["type"] == "incident":
                IncidID = obj["id"]
            elif obj["type"] == "threat-actor":
                taID = obj["id"]
        try:
            SaveObj(db,data["objects"],source,taID,IncidID)
        except:
            with open("error_save_all.log","a") as wf:
                wf.write(f+"\n")

        if "custom_objects" in data.keys():
            SaveObj(db,data["custom_objects"],source,taID,IncidID)


def error_handle(db, epath):
    flist = open(epath).read().split("\n")[:-1]
    IncidID = ""
    taID = ""
    
    for f in flist:
        source = f[58:58+f[58:].index("/")]
        _data = open(f, encoding="utf8").read()
        if _data == "":
            continue

        print (f)
        
        data = json.loads(_data)

        if "objects" not in data.keys():
            with open("save_error_v2.log","a") as wf:
                wf.write(f+"\n")
            continue

        for obj in data["objects"]:
            if obj["type"] == "incident":
                IncidID = obj["id"]
            elif obj["type"] == "threat-actor":
                taID = obj["id"]
        
        try:
            SaveObj(db,data["objects"],source,taID,IncidID)
        except:
            with open("error_save_all.log","a") as wf:
                wf.write(f+"\n")
        





