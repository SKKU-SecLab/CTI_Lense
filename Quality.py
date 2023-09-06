import os

os.chdir("Quality")

print ("* Improper values")
os.system("../venv3/bin/python validtest.py")
print ("")
os.system("../venv3/bin/python validtest_v2.py")
print ("\n\n")

print ("* Improper usage")
print ("----------STIX1----------")
os.system("../venv3/bin/python APinDesc.py")
print ("")
os.system("../venv3/bin/python TAinDesc.py")
print ("")
os.system("../venv3/bin/python TIinDesc.py")
print ("")
os.system("../venv3/bin/python MALinDesc.py")


print ("\n----------STIX2----------")
os.system("../venv3/bin/python APinDesc_v2.py")
print ("")
os.system("../venv3/bin/python MALinDesc_v2.py")
print ("")
os.system("../venv3/bin/python TAinDesc_v2.py")


