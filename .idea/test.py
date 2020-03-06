import pefile
import datetime
import time
import requests
import os

directory= input("Please enter your directory: ")
for filename in os.listdir(directory):
    if filename.endswith(".exe"):
        print("THIS IS FILENAME: " + filename)
        file = filename
        exe_path = directory + "\\" + file
        print("THIS IS EXE_PATH: " + exe_path)

    pe = pefile.PE(exe_path)
    compileTime = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    packed = False
    for field in pe.DOS_HEADER.dump():
        print(field)

    print("\nCompile Time: " + str(compileTime))

    print("\n[*] Listing imported DLLs...")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print('\t' + entry.dll.decode('utf-8'))

    for section in pe.sections:
        ##print(section.Name.decode('utf-8'))
        ##print("\tVirtual Address: " + hex(section.VirtualAddress))
        ##print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
        ##print("\tRaw Size: " + hex(section.SizeOfRawData))
        if int(section.SizeOfRawData) < 1:
            packed = True

    if packed:
        print("Likely packed ")
    else:
        print("File does not appear to be packed")

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': '1b88f1ccceabaa4b8bb643742c0822628f09d2e03fc58374638b73a4c4d1a1a5'}

    files = {'file': ('C:\Windows\System32\calc.exe', open('C:\Windows\System32\calc.exe', 'rb'))}

    response = requests.post(url, files=files, params=params)

    print(response.json())
else:
    print("No .exe found")




### C:\Windows\System32\calc.exe
### C:\Program Files\Core Temp\Core Temp.exe
### 1b88f1ccceabaa4b8bb643742c0822628f09d2e03fc58374638b73a4c4d1a1a5

### https://axcheron.github.io/pe-format-manipulation-with-pefile/

##print(("TimeDateStamp: "+ hex(pe.FILE_HEADER.TimeDateStamp)), exp.name.decode('utf-8'))

##print((pe.FILE_HEADER.TimeDateStamp))

##print("TimeDateStamp: "+ hex(pe.FILE_HEADER.TimeDateStamp))