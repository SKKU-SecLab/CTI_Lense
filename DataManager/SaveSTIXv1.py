import os, fnmatch
import json

from pymongo import MongoClient
from pprint import pprint
from stix.core import STIXPackage
from pymongo.errors import DuplicateKeyError
from pymongo.database import Database

# Function for finding STIX document files.
def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename

# Function for finding all STIX document files.
def find_all_files(path, pattern):
    res = []
    for filename in find_files(path,pattern):
        res.append(filename)

    return res

# Function for saving the Indicator objects in STIX 1
def SaveIndc(db,IndcList,source,taID,incidID,hid):
    collection = db["indicator"]
    for indc in IndcList:
        _indc = dict(indc)
        _indc["_id"] = _indc.pop("id")
        _indc["taID"] = taID
        _indc["incidID"] = incidID
        _indc["hid"] = hid
        
        if "observable" in _indc.keys():
            # print (_indc['observable'].keys())
            if "id" in _indc["observable"].keys():
                SaveObs(db,[_indc["observable"]], source, taID, incidID, hid)
                _indc["observable"] = {"idref": _indc["observable"]["id"]}

#         _indc["date"] = date
        _indc["source"] = source

        try:
            collection.insert_one(_indc)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_indicators\n")

# Function for saving the Observable attributes in Indicator objects in STIX 1
def SaveObs(db,ObsList,source,taID,incidID,hid):
    collection = db["observable"]
    for obs in ObsList:
        _obs = dict(obs)
        _obs["_id"] = _obs.pop("id")
#         _obs["date"] = date
        _obs["source"] = source
        _obs["taID"] = taID
        _obs["incidID"] = incidID
        _obs["hid"] = hid

        try:
            collection.insert_one(_obs)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_observables\n")

# Function for saving the TTP objects in STIX 1
def Savettps(db,ttpList,source,taID,incidID,hid):
    collection = db["ttp"]
    for ttp in ttpList:
        _ttp = dict(ttp)
        _ttp["_id"] = _ttp.pop("id")
 #        _ttp["date"] = date
        _ttp["source"] = source
        _ttp["taID"] = taID
        _ttp["incidID"] = incidID
        _ttp["hid"] = hid

        try:
            collection.insert_one(_ttp)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_ttps\n")

# Function for saving the Threat actor objects in STIX 1
def SaveTA(db,TAList,source,hid):
    collection = db["threat_actor"]
    for ta in TAList:
        _ta = dict(ta)
        _ta["_id"] = _ta.pop("id")
#         _ta["date"] = date
        _ta["source"] = source
        _ta["hid"] = hid
        # collection.insert_one(_ta)

        try:
            collection.insert_one(_ta)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_threat_actors\n")

# Function for saving the Incident objects in STIX 1
def SaveIncid(db,IncidList,source,hid):
    collection = db["incident"]
    for incid in IncidList:
        _incid = dict(incid)
        _incid["_id"] = _incid.pop("id")
#         _incid["date"] = date
        _incid["source"] = source
        _incid["hid"] = hid
        
        # collection.insert_one(_incid)

        try:
            collection.insert_one(_incid)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_incidents\n")

# Function for saving the Exploit target objects in STIX 1
def SaveExpT(db,ExpTList,source,taID,incidID,hid):
    collection = db["exploit_target"]
    for expt in ExpTList:
        _expt = dict(expt)
        _expt["_id"] = _expt.pop("id")
#         _expt["date"] = date
        _expt["source"] = source
        _expt["taID"] = taID
        _expt["incidID"] = incidID
        _expt["hid"] = hid

        if "potential_coas" in _expt.keys():
            if "coas" in _expt["potential_coas"].keys():
                _coas = [coa["course_of_action"]["id"] for coa in _expt["potential_coas"]["coas"]] 
                SaveCOAs(db,_expt["potential_coas"]["coas"],source,taID,incidID,hid)
                _expt["potential_coas"]["coas"] = _coas
        
        try:
            collection.insert_one(_expt)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_exploit_targets\n")
        
# Function for saving the Course of action objects in STIX 1
def SaveCOAs(db,COAList,source,taID,incidID,hid):
    collection = db["course_of_action"]
    for coa in COAList:
        _coa = dict(coa["course_of_action"])
        _coa["_id"] = _coa.pop("id")
#         _coa["date"] = date
        _coa["source"] = source
        _coa["taID"] = taID
        _coa["incidID"] = incidID
        _coa["hid"] = hid
        
        # print (json.dumps(_coa,indent=4,separators=(",",":")))
        
        try:
            collection.insert_one(_coa)
        except DuplicateKeyError:
            pass
        except:
            with open("error.log","a") as wf:
                wf.write(source+"_course_of_actions\n")

# Function for saving the stix_header objects in STIX 1
def SaveSTIXHeader(db,header,source,taID,incidID,hid):
    collection = db["stix_header"]
    _h = dict(header)
    _h["_id"] = hid
#     _h["date"] = date
    _h["source"] = source
    _h["taID"] = taID
    _h["incidID"] = incidID

    # print (json.dumps(_coa,indent=4,separators=(",",":")))
        
    try:
        collection.insert_one(_h)
    except DuplicateKeyError:
        pass
    except:
        with open("error.log","a") as wf:
            wf.write(source+"_stix_header\n")
       
# Function for finding the stix_header objects ID in STIX 1
def findHID(db,header):
    name = "stix_header"
    if "description" in header.keys():
        data = list(db[name].find({"description":header["description"]}))
        if len(data) > 0:
            return data[0]["_id"]
    elif "title" in header.keys():
        data = list(db[name].find({"title":header["title"]}))
        if len(data) > 0:
            return data[0]["_id"]
    elif "handling" in header.keys():
        data = list(db[name].find({"handling.marking_structures.terms_of_use":header["handling"][0]["marking_structures"][1]["terms_of_use"]}))
        if len(data) > 0:
            return data[0]["_id"]
    
    return db[name].count_documents({})+1

# Function for saving one object with different types in STIX 1
def SaveObj(db,STIXData,source):
    taID = ""
    incidID = ""
    hid = ""
    if "threat_actors" in STIXData.keys():
        taID = STIXData["threat_actors"][0]["id"]
    if "incidents" in STIXData.keys():
        incidID = STIXData["incidents"][0]["id"]
    if "stix_header" in STIXData.keys():
        hid = findHID(db,STIXData["stix_header"])
        # pass
 
    for skey, sdata in STIXData.items():
        if skey == "stix_header":
            SaveSTIXHeader(db, sdata, source, taID, incidID, hid)
        elif skey == "indicators":        
            SaveIndc(db, sdata, source, taID, incidID, hid)
        elif skey == "observables":
            SaveObs(db, sdata["observables"], source, taID, incidID, hid)
        elif skey == "threat_actors":
            SaveTA(db, sdata, source, hid)
        elif skey == "ttps":
            Savettps(db, sdata["ttps"], source, taID, incidID, hid)
        elif skey == "incidents":
            SaveIncid(db, sdata, source, hid)
        elif skey == "exploit_targets":
            SaveExpT(db, sdata, source, taID, incidID, hid)

# Function for saving all types of objects in STIX 1
def SaveAll(db,path):
    stix_v1_data = sorted(find_all_files(path, "*.xml"))

    for fpath in stix_v1_data:
        source = fpath.split("/")[2]
        print (source)
        try:
            stix_xml = STIXPackage.from_xml(fpath)
            stix_json = stix_xml.to_dict()
            SaveObj(db, stix_json, source)
        except:
            with open("save_error.log","a") as wf:
                wf.write(fpath+"\n")




