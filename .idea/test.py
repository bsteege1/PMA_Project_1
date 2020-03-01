import pefile

exe_path = "c:\Windows\System32\calc.exe"
pe = pefile.PE(exe_path)

for field in pe.DOS_HEADER.dump():
    print(field)