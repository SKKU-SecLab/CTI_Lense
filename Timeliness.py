from statsmodels.tsa.stattools import grangercausalitytests
import pandas as pd
from datetime import datetime, timedelta

from pymongo import MongoClient
from pymongo.database import Database

import time
import json

if __name__ == "__main__":
    host = "localhost"
    port = 27017

    lags = [i+1 for i in range(30)]

    df = pd.read_csv("causality_data.csv")
    data = grangercausalitytests(df[["secnews","stix"]], maxlag=lags)


