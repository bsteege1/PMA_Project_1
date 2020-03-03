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
    if int(section.SizeOfRawData) < 1 :
        packed = True

if packed:
    print("\nFile is likely packed\n")
else:
    print("\nFile does not appear to be packed\n")

os.system("pause")

### C:\Windows\System32\calc.exe
### C:\Program Files\Core Temp\Core Temp.exe

### https://axcheron.github.io/pe-format-manipulation-with-pefile/

##print(("TimeDateStamp: "+ hex(pe.FILE_HEADER.TimeDateStamp)), exp.name.decode('utf-8'))

##print((pe.FILE_HEADER.TimeDateStamp))

##print("TimeDateStamp: "+ hex(pe.FILE_HEADER.TimeDateStamp))