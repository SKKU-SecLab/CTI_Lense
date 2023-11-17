from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.database import Database

import pandas as pd
import time
import json

path = os.path.dirname(os.path.abspath(__file__))

class Timeliness:

    # Constructor method to initialize the Timeliness class
    def __init__(self):
        # MongoDB connection parameters
        host = "localhost"
        port = 27017
        dbname1 = "STIX1"
        dbname2 = "STIX2"

        # Connect to the MongoDB server
        conn = MongoClient(host=host, port=port)

        # Create instances of custom DBMv1 and DBMv2 classes for managing the databases
        self.dbmv1 = DBMv1(host, port, dbname1, path)
        self.dbmv2 = DBMv2(host, port, dbname2, path)

    # Method to perform Granger causality test on security incident data
    def causality_test(self):
        # Define a range of lags for the Granger causality test
        lags = [i+1 for i in range(30)]

        # Read data from a CSV file for Granger causality test
        df = pd.read_csv(path + "/data/causality_data.csv")
        
        # Perform Granger causality test on the "secnews" and "stix" columns of the DataFrame
        # The results of the test are stored in the 'data' variable
        data = grangercausalitytests(df[["secnews", "stix"]], maxlag=lags)

    # Method to be implemented for Table 2 - Incident Timeliness analysis
    def table2_incident_timeliness(self):
        '''
        We manually find the STIX objects related to the security incident.
        Will update the code.
        '''
        pass


