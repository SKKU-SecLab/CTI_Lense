# CTI_Lense - NDSS 2024 submission

This research artifact is aimed to provide the source code of CTI-Lense, a framework that collates STIX data from a set of open CTI sources and systematically analyzes the collected data, as well as the dataset of various CTI sources.

We shares parts of the code for evaluating Voume, Timeliness, Diversity, and Quality, and all STIX dataset we collected.

## Environment
We tested with Ubuntu 18.04 and Python 3.6.

## Download
You can download the STIX1 and STIX2 data from following drive page:

https://drive.google.com/drive/folders/1X4_Ma8yMW0U-UCN5mVG4N5Z67vr0rIJk

## Installation and virtual environment setting

Clone or download/unzip the source code. Then, download the STIX dataset from the URL link above and unzip file to each folder - **STIX1.zip: CTI_Lense/STIX1, STIX2.zip: CTI_Lense/STIX2**
```
$ cd CTI_Lense
$ virtualenv -p python3 venv3
$ . ./venv/bin/activate
(venv) $ pip install 
```
