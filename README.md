# CTI_Lense - NDSS 2024 submission

This research artifact is aimed to provide the source code of CTI-Lense, a framework that collates STIX data from a set of open CTI sources and systematically analyzes the collected data, as well as the dataset of various CTI sources.

We shares parts of the code for evaluating Volume, Timeliness, Diversity, and Quality, and all STIX dataset we collected.

## Environment
We tested with Ubuntu 18.04 and Python 3.6.

## Download
You can download the STIX1 and STIX2 data from following drive page:

https://drive.google.com/drive/folders/1X4_Ma8yMW0U-UCN5mVG4N5Z67vr0rIJk

## Installation and environment setting
First, install the MongoDB.
```
$ sudo apt-get install mongodb
```
Clone or download/unzip the source code. Then, generate/active python virtualenv environment and install the requirements.
```
$ cd CTI_Lense
$ virtualenv -p python3 venv3
$ . ./venv/bin/activate
(venv3) $ pip install pymongo pandas requests cabby stix stix2 taxii2-client bs4 statsmodels
```
Download the STIX dataset from the URL link above and unzip file to each folder - **STIX1.zip: `CTI_Lense/STIX1`, STIX2.zip: `CTI_Lense/STIX2`**, After you unzip the STIX dataset to each folder, you can import the STIX dataset by executing the ImportData.py.
```
(venv3) python ImportData.py
```

## How to run
### Collecting STIX data and storing data to MondoDB
We recommend you to download the STIX dataset from the drive URL link, however, you can collect the dataset by executing the `.py` code in `CTICollecter` folder and save the dataset to the database by executing the ` SaveData_from_File.py`. The sample execution command is as follows.
```
usage: TAXIIv1.py [-h] -s STIME -e ETIME -o OPATH

optional arguments:
  -h, --help  show this help message and exit
  -s STIME    Start datetime for collecting the STIX data (e.g., 2022-01-01)
  -e ETIME    End datetime for collecting the STIX data (e.g., 2023-01-01)
  -o OPATH    Output directory for STIX data

(venv3) python Collection/TAXIIv1.py -s 2023-01-01 -e 2023-01-03 -o data/STIX1
(venv3) python SaveData_from_File.py -ov1 data/STIX1/
```
### STIX data analysis
You can check the brief analysis for Volume, Timeliness, Diversity, and Quality by executing each `.py` file. Each `.py` file shows following results:
* `Volume.py`: The number of unique objects for each data sources.
* `Timeliness.py`: Granger causality results for daily STIx data and security incidents.
* `Diversity.py`: The number of data for each STIX core object.
* `Quality.py`: The results of Improper value and Improper usage.
```
(venv3) python Volume.py
(venv3) python Timeliness.py
(venv3) python Diversity.py
(venv3) python Quality.py
```

## Results and R script for the Figures
We share the results and R script that we used to draw the figures in our paper in `PaperFig-R/PaperFigs.ipynb`.
