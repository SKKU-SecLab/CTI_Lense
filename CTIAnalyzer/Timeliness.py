import sys
sys.path.append('..')
import os

from DataManager.DBMange import *
from statsmodels.tsa.stattools import grangercausalitytests
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.database import Database

import pandas as pd
import time
import json

path = os.path.dirname(os.path.abspath(__file__))

class Timeliness:

    def __init__(self):
        host = "localhost"
        port = 27017
        dbname1 = "STIX1"
        dbname2 = "STIX2"
        conn = MongoClient(host=host,port=port)

        self.dbmv1 = DBMv1(host, port, dbname1, path)
        self.dbmv2 = DBMv2(host, port, dbname2, path)


    def causality_test(self):
        lags = [i+1 for i in range(30)]

        df = pd.read_csv(path+"/data/causality_data.csv")
        data = grangercausalitytests(df[["secnews","stix"]], maxlag=lags)

    def table2_incident_timeliness(self):
        '''
        We manually find the STIX objects related to the security incident.
        Will update the code.
        '''
        pass

    


