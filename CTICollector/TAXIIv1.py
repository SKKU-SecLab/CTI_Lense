from cabby import create_client

import datetime
import dateutil.parser
import pytz
import json
import os
import time
import subprocess as sp
import sys

from dateutil.relativedelta import relativedelta
from argparse import ArgumentParser


# STIX v1 TAXII server information
# The server information can be added
serverinfo = {
    "Alienvault":{
        "surl":"otx.alienvault.com",
        "discovery":"/taxii/discovery",
        "collections":[
            "user_alienvault",
            "user_BOTNETEXPOSER",
            "user_JNAZARIO",
            "user_YARA_MATCHES",
            "user_JAMESBRINE",
            "user_MALWAREPATROL", 
            "user_CYBERHUNTERAUTOFEED"
        ]
    }
}

def taxii(sinfo, collection, stime, etime):
    results_vo = []

    client = create_client(
            sinfo["surl"],
            use_https=False,
            discovery_path=sinfo["discovery"])

    content_block = client.poll(collection_name=collection, 
            begin_date=stime, end_date=etime)
    
    for block in content_block:
        try:
            results_vo.append(block.content.decode("utf-8"))
        except:
            pass

    return results_vo

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-s", type=str, help="Start datetime for collecting the STIX data (e.g., 2022-01-01)", dest="stime", required=True)
    parser.add_argument("-e", type=str, help="End datetime for collecting the STIX data (e.g., 2023-01-01)", dest="etime", required=True)
    parser.add_argument("-o", type=str, help="Output directory for STIX data", dest="opath", required=True)

    args = parser.parse_args()
    

    stime = datetime.datetime.strptime(args.stime,"%Y-%m-%d")
    stime = stime.replace(tzinfo=datetime.timezone.utc)
    etime = datetime.datetime.strptime(args.etime,"%Y-%m-%d")
    etime = etime.replace(tzinfo=datetime.timezone.utc)

    rpath_v1 = args.opath

    if not rpath_v1.endswith("/"):
        rpath_v1 += "/"

    if not os.path.exists(rpath_v1):
        os.mkdir(rpath_v1) 

    for key, value in serverinfo.items():
        rfpath_v1 = rpath_v1+key+"/"

        if not os.path.exists(rfpath_v1):
            os.mkdir(rfpath_v1)

        for collection in value["collections"]:
            reports_v1 = taxii(serverinfo[key], collection, stime, etime)

            for report in reports_v1:
                with open(rfpath_v1+str(len(os.listdir(rfpath_v1)))+".xml","w") as wf:
                    wf.write(report)



