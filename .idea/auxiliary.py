import pefile
import requests
import datetime
from struct import unpack
from binascii import hexlify, a2b_uu

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



def timeChangedCompiled2():
    # Reference: https://github.com/deptofdefense/SalSA/wiki/PE-File-Format
    def getTimeDateStamp(filename):
        pe = pefile.PE(filename)
        print("TimeDateStamp: " + hex(pe.FILE_HEADER.TimeDateStamp))

    # Reference: https://gist.github.com/geudrik/03152ba1a148d9475e81
    def writeTimeDateStamp(filename, newTimeDateStamp):
        # Open file in read or write binary mode r+b
        try:
            filehandle = open(filename, 'r+b')
            # Check that file opened is Portable Executable file
            if hexlify(filehandle.read(2)) != hexlify(bytes('MZ', encoding="utf8")):
                filehandle.close()
                print("File is not in PE format!")
                return
        except Exception as e:
            print(e)
            return

        # Find the offset of the timeDateStamp and write into it
        try:
            # Get PE offset (@60, DWORD) from DOS header
            #   It's little-endian so we have to flip it
            #   We also need the HEX representation which is an INT value
            filehandle.seek(60, 0)
            offset = filehandle.read(4)
            offset = hexlify(offset[::-1])

            # This was added in due to an issue with offset being set to '' on rare occasions (see comments below)
            if offset == '':
                print("offset is empty")
                filehandle.close()
                return

            #   ValueError: invalid literal for int() with base 16: ''
            #   https://stackoverflow.com/questions/11826054/valueerror-invalid-literal-for-int-with-base-16-x0e-xa3-python
            #   https://stackoverflow.com/questions/20375706/valueerror-invalid-literal-for-int-with-base-10-python
            #       This indicates that for some reason, 'offset' from above is being set as '' and thus can't be converted to a base 16 int
            offset = int(offset, 16)

            # Seek to PE header and read second DWORD
            filehandle.seek(offset + 8, 0)
            filehandle.write(newTimeDateStamp)
            filehandle.close()
        except Exception as e:
            print(e)
            return

    getTimeDateStamp("test.exe")
    # Changing timeDateStamp field to 5c4570dd
    writeTimeDateStamp("test.exe", bytes.fromhex('dd70455c'))
    getTimeDateStamp("test.exe")

def timeChangedCompiled3(pe, filename):
    pe.FILE_HEADER.TimeDateStamp = 692935320
    pe.write(filename)

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

def findStrings (pe):
    # The List will contain all the extracted Unicode strings
    #
    strings = list()

    # Fetch the index of the resource directory entry containing the strings
    #
    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])

    # Get the directory entry
    #
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

    # For each of the entries (which will each contain a block of 16 strings)
    #
    for entry in rt_string_directory.directory.entries:

        # Get the RVA of the string data and
        # size of the string data
        #
        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        print('Directory entry at RVA', hex(data_rva), 'of size', hex(size))
        #print(entry.ResourceDirEntryData.decode('utf-8'))

        # Retrieve the actual data and start processing the strings
        #
        data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
        offset = 0
        while True:
            # Exit once there's no more data to read
            if offset >= size:
                break
            # Fetch the length of the unicode string
            #
            ustr_length = pe.get_word_from_data(data[offset:offset + 2], 0)
            offset += 2

            # If the string is empty, skip it
            if ustr_length == 0:
                continue

            # Get the Unicode string
            #
            ustr = pe.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
            offset += ustr_length * 2
            strings.append(ustr)
            print
            'String of length', ustr_length, 'at offset', offset

