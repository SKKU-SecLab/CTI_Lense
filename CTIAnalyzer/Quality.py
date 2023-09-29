import os
import sys
import json

path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(path)

from quality_test import APinDesc, MALinDesc_v2, TAinDesc, TIinDesc, validtest_v2, APinDesc_v2, MALinDesc, TAinDesc_v2, validtest

from pymongo import MongoClient
from pymongo.database import Database

class Quality:
    def __init__(self):
        host = "localhost"
        port = 27017
        dbname1 = "STIX1"
        dbname2 = "STIX2"
        conn = MongoClient(host=host,port=port)

        self.vtdb = conn["VirusTotal"]
        self.hadb = conn["HybridAnalysis"]
        self.mddb = conn["MetaDefender"]
        self.aptdb = conn["APT_IOC"]

    def fig4_correctness(self):
        print ("* Figure 4 - Proportion of correct and incorrect attribute values")
        print ("  - The numerical values for Figure 4")
        stix1 = validtest.run()
        stix2 = validtest_v2.run()
        print ("="*52)
        print ("{:<22}{:>10}{:>10}{:>10}".format("STIX Objects", "Correct", "Incorrect", "Unmatched"))
        print ("-"*52)
        
        for key,value in stix1.items():
            total = sum([v for k,v in value.items()])
            correct = "{:.2%}".format(stix1[key]["Correct"]/total)
            incorrect = "{:.2%}".format(stix1[key]["Incorrect"]/total)
            unmatched = "{:.2%}".format(stix1[key]["Unmatched"]/total) 
            print ("{:<22}{:>10}{:>10}{:>10}".format(key, correct, incorrect, unmatched))

        for key,value in stix2.items():
            total = sum([v for k,v in value.items()])
            correct = "{:.2%}".format(stix2[key]["Correct"]/total)
            incorrect = "{:.2%}".format(stix2[key]["Incorrect"]/total)
            unmatched = "{:.2%}".format(stix2[key]["Unmatched"]/total) 
            print ("{:<22}{:>10}{:>10}{:>10}".format(key, correct, incorrect, unmatched))

        print ("="*52)


    def table4_scanning_result(self):
        
        stixdata = {"IPdata":43537,"Domaindata":163121,"Filedata":88470,"URIdata":377857}
        cols = ["IPdata","Domaindata","Filedata","URIdata"]
        res = {"IPdata":["43,537"],"Domaindata":["163,121"],"Filedata":["88,470"],"URIdata":["377,857"]}

        for col in cols:
            mquery = {"data.attributes.last_analysis_stats.malicious":{"$gt":0}}
            bquery = {"data.attributes.last_analysis_stats.malicious":{"$eq":0}}
            if col == "Filedata":
                mal = len(self.vtdb[col].distinct("data.attributes.sha256", mquery))
                undet = len(self.vtdb[col].distinct("data.attributes.sha256", bquery))
            else:
                mal = self.vtdb[col].count_documents(mquery)
                undet = self.vtdb[col].count_documents(bquery)
            
            pmal = mal/stixdata[col]
            pundet = undet/stixdata[col]
            n_a = 1-pmal-pundet
            res[col] += ["{:.2%}".format(pmal),"{:.2%}".format(pundet),"{:.2%}".format(n_a)]

        for col in cols:
            if col == "Filedata":
                mquery = {"$and":[{"verdict":{"$ne":"no specific threat"}},
                                    {"verdict":{"$exists":True}}]}
                bquery = {"verdict":"no specific threat"}
                mal = self.hadb[col].count_documents(mquery)
                undet = self.hadb[col].count_documents(bquery)
            elif col == "IPdata":
                mquery = {"result.verdict":"malicious"}
                temp = self.hadb[col].count_documents({})
                mal = self.hadb[col].count_documents(mquery)
                undet = stixdata[col]-mal
            else:
                mquery = {"result":{"$ne":[]}}
                bquery = {"result":[]}
                mal = self.hadb[col].count_documents(mquery)
                undet = self.hadb[col].count_documents(bquery)
            
            pmal = mal/stixdata[col]
            pundet = undet/stixdata[col]
            n_a = 1-pmal-pundet
            res[col] += ["{:.2%}".format(pmal),"{:.2%}".format(pundet),"{:.2%}".format(n_a)]
        
        for col in cols:

            if col == "Filedata":
                mquery = {"scan_results.scan_all_result_i":{"$ne":0}}
                bquery = {"scan_results.scan_all_result_i":{"$eq":0}}
                mal = self.mddb[col].count_documents(mquery)
                undet = self.mddb[col].count_documents(bquery)
            elif col == "IPdata":
                mquery = {"lookup_results.detected_by":{"$ne":0}}
                bquery = {"lookup_results.detected_by":0}
                mal = self.mddb[col].count_documents(mquery)
                undet = self.mddb[col].count_documents(bquery)
            elif col == "Domaindata":
                mal = 29819
                undet = 133090
            else:
                mal = 346564
                undet = 31208
            
            pmal = mal/stixdata[col]
            pundet = undet/stixdata[col]
            n_a = 1-pmal-pundet
            res[col] += ["{:.2%}".format(pmal),"{:.2%}".format(pundet),"{:.2%}".format(n_a)]
        

        print ("* Table IV - Statistics of Indicator objects in the STIX dataset based on observable types and corresponding scanning reports for each commercial scanning service.")
        print ("="*128)
        print ("{:28} | {:^30} | {:^30} | {:^30}".format("","VirusTotal","HybridAnalysis","MetaDefender"))
        print("-"*128)
        print ("{:18}{:>10} | {:>10}{:>10}{:>10} | {:>10}{:>10}{:>10} | {:>10}{:>10}{:>10}".format("Observable types", "Count", "Detected", "Not det.", "N/A","Detected", "Not det.", "N/A","Detected", "Not det.", "N/A"))
        print("-"*128)
        for col in cols:
            print ("{:18}{:>10} | {:>10}{:>10}{:>10} | {:>10}{:>10}{:>10} | {:>10}{:>10}{:>10}".format(*list([col]+res[col])))
        print("="*128)


    def fig5_accuracy_vtt(self):
        cols = ["IPdata","Domaindata","Filedata","URIdata"]
        res = {"IPdata":[],"Domaindata":[],"Filedata":[],"URIdata":[]}
        
        for col in cols:
            if col == "Filedata":
                _len = len(self.vtdb[col].distinct("data.attributes.sha256", {}))
            else:
                _len = self.vtdb[col].count_documents({})

            for i in range(1,41):
                query = {"data.attributes.last_analysis_stats.malicious":{"$gt":i-1}}

                if col == "Filedata":
                    mal = len(self.vtdb[col].distinct("data.attributes.sha256", query))    
                else:
                    mal = self.vtdb[col].count_documents(query)

                res[col].append("{:.6f}".format(mal/_len))
        print ("="*52) 
        print ("{:10}{:>10}{:>12}{:>10}{:>10}".format(*list(["Threshold"]+list(res.keys()))))
        print ("-"*52) 
        for i in range(40):
            print ("{:10}{:>10}{:>12}{:>10}{:>10}".format(*list([str(i)]+[res[key][i] for key in res.keys()])))
        print ("="*52)


    def table5_correctly_mapped(self):
        mapping = {"hash":"FileObjectType","ip":"AddressObjectType",
                    "domain":"DomainNameObjectType","uri":"URIObjectType"}

        aliases = json.loads(open(path+"/data/ta-alias.json").read())
        obsta = json.loads(open(path+"/data/STIXv1_IOC_TA_Map.json").read())
        obsttp = json.loads(open(path+"/data/STIXv1_IOC_TTP_Map.json").read())
        
        print ("="*60)
        print ("{:20}{:15}{:>8}{:>17}".format("Indicator attr.", "Ref. object", "Overlap",  "# (%) Correct"))
        print ("-"*60)

        ta_overlap = 0
        ta_correct = 0

        for k,v in mapping.items():
            apt_ioc = dict([(d["_id"],d) for d in list(self.aptdb[k].find({}))])
            apt_values = list(apt_ioc.keys())
            stix_val = list(obsta[v].keys())
            intersec = set(apt_values) & set(stix_val)

            cnt = 0
            for h in intersec:
                if obsta[v][h] in aliases.keys():
                    for ali in aliases[obsta[v][h]]:
                        if ali in apt_ioc[h]["raw_text"]:
                            cnt+=1
                            break
                else:
                    if obsta[v][h] in apt_ioc[h]["raw_text"]:
                        cnt+=1


            ta_overlap += len(intersec)
            ta_correct += cnt

        # print (ta_overlap, ta_correct)
        print ("{:20}{:15}{:>8}{:>17}".format("Observable","Threat actor","{:,}".format(ta_overlap), "{:,} ({:.2%})".format(ta_correct,ta_correct/ta_overlap)))

        ttp_overlap = 0
        ttp_correct = 0

        for k,v in mapping.items():
            apt_ioc = dict([(d["_id"],d) for d in list(self.aptdb[k].find({}))])
            apt_values = list(apt_ioc.keys())
            stix_val = list(obsttp[v].keys())
            intersec = set(apt_values) & set(stix_val)

            cnt = 0
            for h in intersec:
                if obsttp[v][h] in aliases.keys():
                    for ali in aliases[obsttp[v][h]]:
                        if ali in apt_ioc[h]["raw_text"]:
                            cnt+=1
                            break
                else:
                    if obsttp[v][h] in apt_ioc[h]["raw_text"]:
                        cnt+=1

            ttp_overlap += len(intersec)
            ttp_correct += cnt

        # print (ttp_overlap, ttp_correct)
        print ("{:20}{:15}{:>8}{:>17}".format("(STIX 1)","TTP","{:,}".format(ttp_overlap),"{:,} ({:.2%})".format(ttp_correct,ttp_correct/ttp_overlap)))

        print ("-"*60)
        obsta = json.loads(open(path+"/data/STIXv2_IOC_TA_Map.json").read())

        ta_overlap = 0
        ta_correct = 0

        for k, v in mapping.items():
            apt_ioc = dict([(d["_id"],d) for d in list(self.aptdb[k].find({"threat_actor":{"$ne": []}}))])
            apt_ip = list(apt_ioc.keys())
            stixioc = list(obsta[k].keys())
            intersec = set(apt_ip) & set(stixioc)

            cnt = 0

            for h in intersec:
                ck = 0
                if obsta[k][h] in aliases.keys():
                    for ali in aliases[obsta[k][h]]:
                        if ali.lower() in apt_ioc[h]["raw_text"].lower():
                            ck = 1
                            cnt+=1
                            break
                else:
                    if obsta[k][h].lower() in apt_ioc[h]["raw_text"].lower():
                        cnt+=1
                        ck = 1

            ta_overlap += len(intersec)
            ta_correct += cnt


        # print (ta_overlap, ta_correct)
        print ("{:20}{:15}{:>8}{:>17}".format("Pattern","Threat actor","{:,}".format(ta_overlap), "{:,} ({:.2%})".format(ta_correct,ta_correct/ta_overlap)))
        
        obsmal = json.loads(open(path+"/data/STIXv2_IOC_MAL_Map.json").read())

        mal_overlap = 0
        mal_correct = 0

        for k, v in mapping.items():
            apt_ioc = dict([(d["_id"],d) for d in list(self.aptdb[k].find({"malware_family":{"$ne": []}}))])
            apt_ip = list(apt_ioc.keys())
            stixioc = list(obsmal[k].keys())
            intersec = set(apt_ip) & set(stixioc)

            cnt = 0

            for h in intersec:
                for d in obsmal[k][h]:
                    if d.lower() in apt_ioc[h]["raw_text"].lower():
                        cnt+=1

            mal_overlap += len(intersec)
            mal_correct += cnt

        # print (mal_overlap, mal_correct)
        print ("{:20}{:15}{:>8}{:>17}".format("(STIX 2)","TTP","{:,}".format(mal_overlap), "{:,} ({:.2%})".format(mal_correct,mal_correct/mal_overlap)))
        print ("="*60)


    def fig7_completeness(self):
        print ("* Figure 7 - Number of indicator objects where information is written in the Description attribute and the precise object/attribute for four information types: Attack pattern (AP), Malware instance (MI), Threat actor (TA), and Target information (TI)")
        print ("="*60)
        print ("{:<14}{:<20}{:>13}{:>13}".format("STIX version","Information type", "Description", "Object/Attr"))
        print ("-"*60)
        ap, mi, ta, ti = APinDesc.run(), MALinDesc.run(), TAinDesc.run(), TIinDesc.run() 
        print ("{:<14}{:<20}{:>13}{:>13}".format("STIX 1", "Attack pattern", "{:,}".format(ap[0]), "{:,}".format(ap[1])))
        print ("{:<14}{:<20}{:>13}{:>13}".format("", "Malware instance", "{:,}".format(mi[0]), "{:,}".format(mi[1])))
        print ("{:<14}{:<20}{:>13}{:>13}".format("", "Threat actor", "{:,}".format(ta[0]), "{:,}".format(ta[1])))
        print ("{:<14}{:<20}{:>13}{:>13}".format("", "Target information", "{:,}".format(ti[0]), "{:,}".format(ti[1])))

        print ("-"*60)
        ap, mi, ta = APinDesc_v2.run(), MALinDesc_v2.run(), TAinDesc_v2.run() 
        print ("{:<14}{:<20}{:>13}{:>13}".format("STIX 2", "Attack pattern", "{:,}".format(ap[0]), "{:,}".format(ap[1])))
        print ("{:<14}{:<20}{:>13}{:>13}".format("", "Malware instance", "{:,}".format(mi[0]), "{:,}".format(mi[1])))
        print ("{:<14}{:<20}{:>13}{:>13}".format("", "Threat actor", "{:,}".format(ta[0]), "{:,}".format(ta[1])))
        print ("{:<14}{:<20}{:>13}{:>13}".format("", "Target information", 0, 0))

        print ("="*60)
    


