# PMA_Project_1
COSC 4010 Binary Analysis Project 1

Group Members: Brandon Steege, Hannah Tippin, Leonardo Garcia
Group Name: Click here for more ram!!1!

The purpose of our program is to analyze a directory of files to allow the user to potentially determine if the given files are malware. Our code goes through each .exe or .dll file in a given directory and looks for strings, lists imports, checks if the file is packed, runs the file through VirusTotal, and gets the compile time. 

For the second part of this project, we decided to change the compile time of a given file in the directory that is being searched. If the user decided to change the compile time, a new .exe will be created within the python project directory. This new file will be called new"original filename".exe. This new file still runs and functions the same as the original. This functionality allows the user to directly compare the original and new files side by side. 



Testing And Outputs


Chapter 1 Malware Directory:

C:\Users\User\Anaconda3\envs\PMA_Project_1\python.exe C:/Users/User/PycharmProjects/PMA_Project_1/.idea/main.py
Please enter your directory: C:\Users\User\Desktop\Malware\Practical Malware Analysis Labs\BinaryCollection\Chapter_1L


[*] File Found: Lab01-01.dll

[*] Virus Total Scan Link:
{'scan_id': 'f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba-1585620460', 'sha1': 'a4b35de71ca20fe776dc72d12fb2886736f43c22', 'resource': 'f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba', 'response_code': 1, 'sha256': 'f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba', 'permalink': 'https://www.virustotal.com/file/f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba/analysis/1585620460/', 'md5': '290934c61de9176ad682ffdd65f0a669', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 2010-12-19 08:16:38

[*] File does not appear to be packed

[*] Listing imported DLLs...
	KERNEL32.dll
	WS2_32.dll
	MSVCRT.dll

[*] Kernel32.dll imports:
	Sleep at 0x10002000
	CreateProcessA at 0x10002004
	CreateMutexA at 0x10002008
	OpenMutexA at 0x1000200c
	CloseHandle at 0x10002010

[*] Listing all potentially interesting strings in rData: 
	00CloseHandle
	02Sleep
	00CreateProcessA
	00CreateMutexA
	01OpenMutexA
	00KERNEL32.dll
	00WS2_32.dll
	02strncmp
	00MSVCRT.dll
	01_initterm
	02malloc
	00_adjust_fdiv

Would you like to change the compile time?
Enter y for yes: y

[*] New Compile Time: 1991-12-16 18:02:00


[*] File Found: Lab01-01.exe

[*] Virus Total Scan Link:
{'scan_id': '58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47-1585620659', 'sha1': '9dce39ac1bd36d877fdb0025ee88fdaff0627cdb', 'resource': '58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47', 'response_code': 1, 'sha256': '58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47', 'permalink': 'https://www.virustotal.com/file/58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47/analysis/1585620659/', 'md5': 'bb7425b82141a1c0f7d60e5106676bb1', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 2010-12-19 08:16:19

[*] File does not appear to be packed

[*] Listing imported DLLs...
	KERNEL32.dll
	MSVCRT.dll

[*] Kernel32.dll imports:
	CloseHandle at 0x00402000
	UnmapViewOfFile at 0x00402004
	IsBadReadPtr at 0x00402008
	MapViewOfFile at 0x0040200c
	CreateFileMappingA at 0x00402010
	CreateFileA at 0x00402014
	FindClose at 0x00402018
	FindNextFileA at 0x0040201c
	FindFirstFileA at 0x00402020
	CopyFileA at 0x00402024

[*] Listing all potentially interesting strings in rData: 
	00CloseHandle
	02UnmapViewOfFile
	01IsBadReadPtr
	01MapViewOfFile
	00CreateFileMappingA
	00CreateFileA
	00FindClose
	00FindNextFileA
	00FindFirstFileA
	00CopyFileA
	00KERNEL32.dll
	02malloc
	00MSVCRT.dll
	00_exit
	00_XcptFilter
	00__p___initenv
	00__getmainargs
	01_initterm
	00__setusermatherr
	00_adjust_fdiv
	00__p__commode
	00__p__fmode
	00__set_app_type
	00_except_handler3
	00_controlfp
	01_stricmp

Would you like to change the compile time?
Enter y for yes: y

[*] New Compile Time: 1991-12-16 18:02:00


[*] File Found: Lab01-02.exe

[*] Virus Total Scan Link:
{'scan_id': 'c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6-1585620464', 'sha1': '5a016facbcb77e2009a01ea5c67b39af209c3fcb', 'resource': 'c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6', 'response_code': 1, 'sha256': 'c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6', 'permalink': 'https://www.virustotal.com/file/c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6/analysis/1585620464/', 'md5': '8363436878404da0ae3e46991e355b83', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 2011-01-19 08:10:41

[*] File is Likely packed 

[*] Listing imported DLLs...
	KERNEL32.DLL
	ADVAPI32.dll
	MSVCRT.dll
	WININET.dll

[*] Kernel32.dll imports:
	LoadLibraryA at 0x00406064
	GetProcAddress at 0x00406068
	VirtualProtect at 0x0040606c
	VirtualAlloc at 0x00406070
	VirtualFree at 0x00406074
	ExitProcess at 0x00406078

[*] Advapi32.dll imports:
	CreateServiceA at 0x00406080

[*] Listing all potentially interesting strings in rData: 
	fca\\`Y
	14\\k\r|
	8aMalService
	a4sHGL345
	07http://w
	1ewarean
	07ysisbook.co
	dbom#Int6net Explo!r 8FEI
	01SystemTimeToFile
	15GetMo
	f3*Waitab\'r
	0fProcess
	0cOpenMu$x
	13ObjectU4
	bag\rTh
	a0[Vrtb
	0eCtrlDisp ch
	ce5nm@_
	eddlI37n
	a7lB`.rd
	7fXPTPSW

Would you like to change the compile time?
Enter y for yes: y

[*] New Compile Time: 1991-12-16 18:02:00


[*] File Found: Lab01-03.exe

[*] Virus Total Scan Link:
{'scan_id': '7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec-1585620467', 'sha1': '290ab6f431f46547db2628c494ce615d6061ceb8', 'resource': '7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec', 'response_code': 1, 'sha256': '7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec', 'permalink': 'https://www.virustotal.com/file/7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec/analysis/1585620467/', 'md5': '9c5c27494c28ed0b14853b346b113145', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 1969-12-31 16:00:00

[*] File is Likely packed 

[*] Listing imported DLLs...
	KERNEL32.dll

[*] Kernel32.dll imports:
	LoadLibraryA at 0x00405128
	GetProcAddress at 0x0040512c

[*] Listing all potentially interesting strings in rData: 
	8b3Bt>O
	1c2]<,M
	ad S>VW
	1bI*G9>
	00ole32.vd
	01}OLEAUTLA
	c0IMSVCRTT"b
	03_getmas
	d6|P2r3Us
	9cp|vuy
	dft)\r4p

Would you like to change the compile time?
Enter y for yes: y

[*] New Compile Time: 1991-12-16 18:02:00


[*] File Found: Lab01-04.exe

[*] Virus Total Scan Link:
{'scan_id': '0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126-1585620470', 'sha1': '9369d80106dd245938996e245340a3c6f17587fe', 'resource': '0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126', 'response_code': 1, 'sha256': '0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126', 'permalink': 'https://www.virustotal.com/file/0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126/analysis/1585620470/', 'md5': '625ac05fd47adc3c63700c3b30de79ab', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 2019-08-30 15:26:59

[*] File does not appear to be packed

[*] Listing imported DLLs...
	KERNEL32.dll
	ADVAPI32.dll
	MSVCRT.dll

[*] Kernel32.dll imports:
	GetProcAddress at 0x00402010
	LoadLibraryA at 0x00402014
	WinExec at 0x00402018
	WriteFile at 0x0040201c
	CreateFileA at 0x00402020
	SizeofResource at 0x00402024
	CreateRemoteThread at 0x00402028
	FindResourceA at 0x0040202c
	GetModuleHandleA at 0x00402030
	GetWindowsDirectoryA at 0x00402034
	MoveFileA at 0x00402038
	GetTempPathA at 0x0040203c
	GetCurrentProcess at 0x00402040
	OpenProcess at 0x00402044
	CloseHandle at 0x00402048
	LoadResource at 0x0040204c

[*] Advapi32.dll imports:
	OpenProcessToken at 0x00402000
	LookupPrivilegeValueA at 0x00402004
	AdjustTokenPrivileges at 0x00402008

[*] Listing all potentially interesting strings in rData: 
	00CloseHandle
	01OpenProcess
	00GetCurrentProcess
	00CreateRemoteThread
	01GetProcAddress
	01LoadLibraryA
	02WinExec
	02WriteFile
	00CreateFileA
	02SizeofResource
	01LoadResource
	00FindResourceA
	01GetModuleHandleA
	01GetWindowsDirectoryA
	01MoveFileA
	01GetTempPathA
	00KERNEL32.dll
	00AdjustTokenPrivileges
	00LookupPrivilegeValueA
	01OpenProcessToken
	00ADVAPI32.dll
	01_snprintf
	00MSVCRT.dll
	00_exit
	00_XcptFilter
	00__p___initenv
	00__getmainargs
	01_initterm
	00__setusermatherr
	00_adjust_fdiv
	00__p__commode
	00__p__fmode
	00__set_app_type
	00_except_handler3
	00_controlfp
	01_stricmp

Would you like to change the compile time?
Enter y for yes: y

[*] New Compile Time: 1991-12-16 18:02:00

[*] Directory contains no untested files.

Process finished with exit code 0




Malware VM Program Files Directory:

C:\Users\User\Anaconda3\envs\PMA_Project_1\python.exe C:/Users/User/PycharmProjects/PMA_Project_1/.idea/main.py
Please enter your directory: C:\Program Files

[*] Directory contains no untested files.

Process finished with exit code 0


Note: The reason no executables were tested is because our program only analyzes the directory to find executables and .dll files. There is no functionality that allows the sub directories to have their contents analyzed as well. 
