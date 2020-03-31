# auxiliary.py
# Authors: Brandon Steege, Hannah Tippin, Leonardo Garcia
# COSC 4010
# 3 Apr 2020

import pefile
import requests
import datetime

def virusTotal(pe, fullDirectory):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': '1b88f1ccceabaa4b8bb643742c0822628f09d2e03fc58374638b73a4c4d1a1a5'}
    files = {'file': (fullDirectory, open(fullDirectory, 'rb'))}
    response = requests.post(url, files=files, params=params)
    print("\n[*] Virus Total Scan Link:");
    print(response.json())

def timeCompiled (pe):
    compileTime = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    print("\n[*] Compile Time: " + str(compileTime))

def changeCompileTime(pe, filename):
    pe.FILE_HEADER.TimeDateStamp = 692935320
    pe.write("new" + filename)

def isPacked (pe):
    packed = False
    for section in pe.sections:
        if int(section.SizeOfRawData) < 1:
            packed = True
    if packed:
        print("\n[*] File is Likely packed ")
    else:
        print("\n[*] File does not appear to be packed")

def importedDlls (pe):
    print("\n[*] Listing imported DLLs...")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print('\t' + entry.dll.decode('utf-8'))

def detectImports(pe):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode('utf-8').lower()
        if dll_name == "kernel32.dll":
            print("\n[*] Kernel32.dll imports:")
            for func in entry.imports:
                print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
        elif dll_name == "mscvrt.dll":
            print("\n[*] MSCVRT.dll imports:")
            for func in entry.imports:
                print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
        elif dll_name == "advapi32.dll":
            print("\n[*] Advapi32.dll imports:")
            for func in entry.imports:
                print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))

def findStrings(pe):
    print("\n[*] Listing all potentially interesting strings in rData: ")
    rData = str(pe.sections[1].get_data())
    strings = rData.split("\\x")
    for x in strings:
        if len(x) >= 7:
         print("\t" + x)
