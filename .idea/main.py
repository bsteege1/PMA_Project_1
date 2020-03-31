import pefile
import os
import auxiliary
import datetime

directory = input("Please enter your directory: ")
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

        answer= input("\nWould you like to change the compile time?\nEnter y for yes: ")
        if(answer =='y'):
            auxiliary.changeCompileTime(pe, filename)
            compileTime = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            print("\n[*] New Compile Time: " + str(compileTime))


else:
    print("\n[*] Directory contains no untested executables")



### Virus Total Temporary Key: 1b88f1ccceabaa4b8bb643742c0822628f09d2e03fc58374638b73a4c4d1a1a5
