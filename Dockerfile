# Use the official Ubuntu image as the base image
FROM ubuntu:18.04

# Update and upgrade the package list
RUN apt-get update 

# worker directory
WORKDIR /CTI_Lense

COPY ./CTI_Lense ./

# Install any additional packages you need
RUN apt-get install -y mongodb python3 python3-pip unzip

RUN pip3 install pymongo pandas requests cabby stix stix2 taxii2-client bs4 statsmodels 

CMD ["/bin/bash"]

