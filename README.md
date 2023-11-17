# CTI_Lense - NDSS 2024 Artifact

Welcome to the GitHub-repository for CTI-Lense. This repository hosts the artifacts for CTI-Lense, a framework dedicated to cyber threat intelligence (CTI) analysis. Here are what you will find in this repository:

- **STIX Dataset:** Access our extensive dataset of STIX data we used for our analysis.
- **Source Code:** Get the CTI-Lense framework's source code, designed for efficient collection and processing of STIX data from various open CTI sources. The code for replicating our research results (**Volumne**, **Timeliness**, and **Quality**) are also included.
- **Research paper:** Take a look at the design and evaluation results of CTI-Lense, which are detailed in our [NDSS 2024 paper](https://seclab.skku.edu/wp-content/uploads/2023/11/SharingCTI.pdf) (preprint version without author information). The authors and their affiliation information are as follows.
> Beomjin Jin, Eunsoo Kim, Hyunwoo Lee, Elisa Bertino, Doowon Kim, and Hyoungshick Kim. <br>
Sharing cyber threat intelligence: Does it really help? <br>
In Proceedings of the Network and Distributed System Security (NDSS) Symposium 2024.

# How to use
There are two ways to replicate our analysis result:
- [Step 1](#step1). **(Recommended)** Simply use our docker image and run.
- [Step 2](#step2). **(Optional)** Set the analysis environment manually from scratch.
- [Optinal step](#optional). **(Optional)** This step is provided in case you are curious about how we built the docker image.

<a name="step1"></a>
## Step 1. Directly using our docker image (Recommended)
The step is recommended if you want to replicate our analysis result without having to set the analysis environment manually.

### 1. Pull the docker image

```
$ sudo apt-get install docker.io
$ sudo docker pull jinbumjin/cti-lenseps:artifact
$ sudo docker run -it jinbumjin/cti-lense:artifact /bin/bash
```

### 2. How to run
First, start the MongoDB service in the docker container. It takes up to 10 minutes to enable the MongoDB service. 
```
/CTI_Lense# service mongodb start
```

Then, to get our experimental results, simply run CTI_Lense.py code with the following commands in the docker container:
```
/CTI_Lense# python3 CTI_Lense.py -e timeliness
/CTI_Lense# python3 CTI_Lense.py -e diversity
/CTI_Lense# python3 CTI_Lense.py -e quality
```

If you wish to know more about how we built the docker image, you can follow descriptions in the [Optinal step](#optional)

<a name="step2"></a>
## Step 2. Manual environment setting (Optional)
This is part is optional. Only follow below steps in case you want to **recreate the analysis environment from scratch.**

### 1. Environment
We tested with Ubuntu 18.04 and Python 3.6.

### 2. Dataset download
You can download the following data from the drive pages:
* STIX dataset: STIX1.zip and STIX2.zip 
* IOC dataset from APT reports: APT_IOC.zip
* Scanning reports dataset from VirusTotal, HybridAnalysis, and MetaDefender: ScanningReport.zip

https://drive.google.com/drive/folders/1X4_Ma8yMW0U-UCN5mVG4N5Z67vr0rIJk

or 

https://figshare.com/articles/dataset/STIX_dataset/24126336

### 3. Installation and environment setting
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
Download the STIX, APT_IOC, and scanning report dataset from the URL link above and unzip file to each folder in `dbdata/` folder. The correct file locations and folders are as follows:
```
CTI_Lense/
|-- CTI_Lense.py
|-- ImportData.py
|-- SaveData_from_File.py
|-- dbdata/
   |-- STIX1/
      |-- course_of_action.json
      |-- exploit_target.json
      |-- incident.json
      |-- ...
   |-- STIX2/
      |-- attack-pattern.json
      |-- campaign.json
      |-- course-of-action.json
      |-- ...
   |-- APT_IOC/
      |-- domain.json
      |-- hash.json
      |-- ip.json
      |-- uri.json
   |-- ScanReport/
      |-- HybridAnalysis/
         | -- Domaindata.json
         | -- Filedata.json
         | -- IPdata.json
         | -- URIdata.json
      |-- MetaDefender/
         | -- Domaindata.json
         | -- Filedata.json
         | -- IPdata.json
         | -- URIdata.json
      |-- VirusTotal/
         | -- Domaindata.json
         | -- Filedata.json
         | -- IPdata.json
         | -- URIdata.json
|-- ...

```

After you unzip the datasets to the right place of folders, you can import the STIX dataset by executing the ImportData.py.
```
(venv3) python ImportData.py
```
### How to run
#### Collecting STIX data and storing data to MondoDB
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
### STIX data analysis results
You can check the brief analysis for Volume, Timeliness, Diversity, and Quality by executing the `CTI_Lense.py` file. You can get individual results for Volume, Timeliness, Diversity, and Quality with the `-e` parameter. The sample usage and result are as follows.
```
(venv3) python CTI_Lense.py --help
usage: CTI_Lense.py [-h] [-e ETYPE]

optional arguments:
  -h, --help  show this help message and exit
  -e ETYPE    You can see individual results for one of volume, diversity,
              timeliness, and qaulity. Please, choose one of volume,
              diversity, timeliness, and qaulity. If you choose none, the code
              will shows all results

(venv3) python CTI_Lense.py -e diversity
* Table III - Objects and attributes used in STIX dataset
====================================================
STIX version             Objects        Attributes
----------------------------------------------------
STIX 1                 Count   Prop.   Usage   Prop.
----------------------------------------------------
campaign                   0   0.00%    0/20   0.00%
course_of_action       3,768   0.10%    5/19  26.32%
exploit_target        10,789   0.28%    6/15  40.00%
incident              29,086   0.75%    4/34  11.76%
indicator          3,846,499  98.77%   13/25  52.00%
threat_actor             719   0.02%    3/20  15.00%
ttp                    3,734   0.10%   10/18  55.56%
report                     0   0.00%    0/14   0.00%
----------------------------------------------------
STIX 2                 Count   Prop.   Usage   Prop.
----------------------------------------------------
attack-pattern         1,662   0.07%   12/18  66.67%
campaign                 151   0.01%    9/20  45.00%
course-of-action       1,181   0.05%   11/16  68.75%
grouping                   0   0.00%    0/18   0.00%
identity               1,110   0.04%   12/20  60.00%
indicator          2,342,261  94.93%   18/23  78.26%
infrastructure             0   0.00%    0/21   0.00%
intrusion-set            211   0.01%   12/23  52.17%
location                   1   0.00%    9/25  36.00%
malware                2,733   0.11%   16/26  61.54%
malware-analysis           0   0.00%    0/30   0.00%
note                       0   0.00%    0/18   0.00%
observed-data          5,087   0.21%   12/19  63.16%
opinion                    0   0.00%    0/18   0.00%
report                57,165   2.32%   14/19  73.68%
threat-actor             723   0.03%   10/27  37.04%
tool                     491   0.02%   11/20  55.00%
vulnerability          5,755   0.23%   11/16  68.75%
relationship          47,666   1.93%   12/20  60.00%
sighting               1,273   0.05%   11/22  50.00%
====================================================
...
```

### Results and R script for the Figures
We share the results and R script that we used to draw the figures in our paper in `PaperFig-R/PaperFigs.ipynb`.

<a name="optional"></a>
## How we built the docker image (Optional)
(This part is strictly optional, only follow below steps if you want to build the docker image yourself.)
First, download the code and place the 'CTI_Lense' folder and the 'Dockerfile' as shown below. Then, build and run the Docker image, and enable the MongoDB service within the Docker container.

```
$ ls
CTI_Lense   Dockerfile

$ sudo docker build -t ctilense:1.0 .
$ sudo docker run -it ctilense:1.0 /bin/bash
/CTI_Lense# service mongodb start
```

Second, you must follow the **Manual environment setting** [step](#manual_setting). This involves downloading the datasets and importing them into MongoDB, except the installation of depedencies (apt-get and pip). Afterwards, commit the new container image to the host.

```
$ sudo docker ps
CONTAINER ID   IMAGE		...
ed4094713497   ctilense:1.0	...

$ sudo docker commit ed4094713497 ctilense:1.1
```
