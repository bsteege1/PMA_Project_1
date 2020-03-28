import pefile
import os
import auxiliary


directory= input("Please enter your directory: ")
for filename in os.listdir(directory):
    if filename.endswith(".exe") or filename.endswith(".dll"):
        print("\n\n[*] EXE Found: " + filename)
        fullDirectory = directory + "\\" + filename
        pe = pefile.PE(fullDirectory)

        #Upload to virustotal
        auxiliary.virusTotal(pe, fullDirectory)

        #Find compilation time of file
        auxiliary.timeCompiled(pe)

        #Decide whether file is packed
        auxiliary.isPacked(pe)

        #List Imported DLLs
        auxiliary.importedDlls(pe)

        auxiliary.detectImports(pe)

        #Find Strings
        auxiliary.findStrings(pe)

        answer= input("Would you like to change the compile time?")
        if(answer=='y'):
            auxiliary.timeChangedCompiled()

else:
    print("\n[*] Directory contains no untested executables")


### C:\Windows\Syste\calc.exem32
### C:\Program Files\Core Temp\Core Temp.exe
### 1b88f1ccceabaa4b8bb643742c0822628f09d2e03fc58374638b73a4c4d1a1a5

### https://axcheron.github.io/pe-format-manipulation-with-pefile/