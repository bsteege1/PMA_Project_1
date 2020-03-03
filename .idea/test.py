import pefile
import datetime
import time
import os


exe_path = input("Please enter your file path : ")
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
    if int(section.SizeOfRawData) < 1 :
        packed = True

if packed:
    print("Likely packed ")
else:
    print("File does not appear to be packed")

os.system("pause")

### C:\Windows\System32\calc.exe
### C:\Program Files\Core Temp\Core Temp.exe

### https://axcheron.github.io/pe-format-manipulation-with-pefile/

##print(("TimeDateStamp: "+ hex(pe.FILE_HEADER.TimeDateStamp)), exp.name.decode('utf-8'))

##print((pe.FILE_HEADER.TimeDateStamp))

##print("TimeDateStamp: "+ hex(pe.FILE_HEADER.TimeDateStamp))