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



A really long output of our program running on an actual .exe called CoreTemp

Please enter your directory: C:\Program Files\Core Temp


[*] EXE Found: Core Temp.exe

[*] Virus Total Scan Link:
{'scan_id': '117db083d9b5d09113287bf1aa9b40c2a977acbff097efa62065a9540f36b0d3-1585622271', 'sha1': '9dd2645fae2f793cbc2a60a2340a8016d0bb0218', 'resource': '117db083d9b5d09113287bf1aa9b40c2a977acbff097efa62065a9540f36b0d3', 'response_code': 1, 'sha256': '117db083d9b5d09113287bf1aa9b40c2a977acbff097efa62065a9540f36b0d3', 'permalink': 'https://www.virustotal.com/file/117db083d9b5d09113287bf1aa9b40c2a977acbff097efa62065a9540f36b0d3/analysis/1585622271/', 'md5': '335c88d0e5cc666e4c4bbb864cb1a814', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 2019-08-17 14:38:57

[*] File does not appear to be packed

[*] Listing imported DLLs...
	COMCTL32.dll
	POWRPROF.dll
	gdiplus.dll
	KERNEL32.dll
	USER32.dll
	GDI32.dll
	COMDLG32.dll
	ADVAPI32.dll
	SHELL32.dll
	ole32.dll
	OLEAUT32.dll
	SHLWAPI.dll
	SETUPAPI.dll
	WS2_32.dll
	VERSION.dll

[*] Kernel32.dll imports:
	DeviceIoControl at 0x14008a1c0
	FindNextFileW at 0x14008a1c8
	FreeResource at 0x14008a1d0
	LockResource at 0x14008a1d8
	LoadResource at 0x14008a1e0
	FindResourceW at 0x14008a1e8
	EnumResourceNamesW at 0x14008a1f0
	GetUserDefaultUILanguage at 0x14008a1f8
	QueryPerformanceFrequency at 0x14008a200
	QueryPerformanceCounter at 0x14008a208
	LocalAlloc at 0x14008a210
	lstrcpynW at 0x14008a218
	FreeLibrary at 0x14008a220
	LoadLibraryW at 0x14008a228
	GetFileSize at 0x14008a230
	TerminateThread at 0x14008a238
	SetErrorMode at 0x14008a240
	SetFileAttributesW at 0x14008a248
	RemoveDirectoryW at 0x14008a250
	SetThreadPriority at 0x14008a258
	SetPriorityClass at 0x14008a260
	WaitForMultipleObjects at 0x14008a268
	ReadFile at 0x14008a270
	GetModuleFileNameA at 0x14008a278
	GetVersion at 0x14008a280
	HeapReAlloc at 0x14008a288
	WriteConsoleW at 0x14008a290
	FlushFileBuffers at 0x14008a298
	SetStdHandle at 0x14008a2a0
	GetCurrentProcessId at 0x14008a2a8
	GetEnvironmentStringsW at 0x14008a2b0
	FreeEnvironmentStringsW at 0x14008a2b8
	LCMapStringW at 0x14008a2c0
	SetFilePointer at 0x14008a2c8
	DeleteCriticalSection at 0x14008a2d0
	GetFileType at 0x14008a2d8
	VerSetConditionMask at 0x14008a2e0
	GetStringTypeW at 0x14008a2e8
	HeapSize at 0x14008a2f0
	IsValidCodePage at 0x14008a2f8
	GetOEMCP at 0x14008a300
	GetACP at 0x14008a308
	GetCPInfo at 0x14008a310
	GetTimeZoneInformation at 0x14008a318
	FlsAlloc at 0x14008a320
	GetCurrentThreadId at 0x14008a328
	WideCharToMultiByte at 0x14008a330
	FlsFree at 0x14008a338
	FlsSetValue at 0x14008a340
	FlsGetValue at 0x14008a348
	InitializeCriticalSectionAndSpinCount at 0x14008a350
	GetConsoleMode at 0x14008a358
	GetConsoleCP at 0x14008a360
	LeaveCriticalSection at 0x14008a368
	EnterCriticalSection at 0x14008a370
	HeapCreate at 0x14008a378
	HeapSetInformation at 0x14008a380
	GetStdHandle at 0x14008a388
	ExitProcess at 0x14008a390
	TerminateProcess at 0x14008a398
	RtlCaptureContext at 0x14008a3a0
	RtlVirtualUnwind at 0x14008a3a8
	IsDebuggerPresent at 0x14008a3b0
	SetUnhandledExceptionFilter at 0x14008a3b8
	UnhandledExceptionFilter at 0x14008a3c0
	GetStartupInfoW at 0x14008a3c8
	GetCommandLineW at 0x14008a3d0
	DeleteFileA at 0x14008a3d8
	RtlPcToFileHeader at 0x14008a3e0
	RaiseException at 0x14008a3e8
	HeapFree at 0x14008a3f0
	GetTimeFormatW at 0x14008a3f8
	EncodePointer at 0x14008a400
	DecodePointer at 0x14008a408
	GetSystemTimeAsFileTime at 0x14008a410
	RtlUnwindEx at 0x14008a418
	RtlLookupFunctionEntry at 0x14008a420
	HeapAlloc at 0x14008a428
	MultiByteToWideChar at 0x14008a430
	FindFirstFileW at 0x14008a438
	FindClose at 0x14008a440
	GetFileSizeEx at 0x14008a448
	GetFullPathNameW at 0x14008a450
	VerifyVersionInfoW at 0x14008a458
	GetModuleHandleW at 0x14008a460
	GetProcAddress at 0x14008a468
	GetVersionExW at 0x14008a470
	GetLocalTime at 0x14008a478
	GetTickCount at 0x14008a480
	GetModuleFileNameW at 0x14008a488
	Sleep at 0x14008a490
	MulDiv at 0x14008a498
	GetLastError at 0x14008a4a0
	CreateFileA at 0x14008a4a8
	CompareStringW at 0x14008a4b0
	SetEnvironmentVariableW at 0x14008a4b8
	SetEndOfFile at 0x14008a4c0
	GetProcessHeap at 0x14008a4c8
	SetEnvironmentVariableA at 0x14008a4d0
	GetExitCodeThread at 0x14008a4d8
	LoadLibraryA at 0x14008a4e0
	CreateThread at 0x14008a4e8
	GetCurrentThread at 0x14008a4f0
	GetCurrentProcess at 0x14008a4f8
	GetDateFormatW at 0x14008a500
	FormatMessageW at 0x14008a508
	LocalFree at 0x14008a510
	UnmapViewOfFile at 0x14008a518
	CreateMutexW at 0x14008a520
	WaitForSingleObject at 0x14008a528
	CreateFileMappingW at 0x14008a530
	MapViewOfFile at 0x14008a538
	CreateFileW at 0x14008a540
	WriteFile at 0x14008a548
	DeleteFileW at 0x14008a550
	OpenMutexW at 0x14008a558
	ReleaseMutex at 0x14008a560
	SetLastError at 0x14008a568
	CloseHandle at 0x14008a570
	SetHandleCount at 0x14008a578

[*] Advapi32.dll imports:
	RegDeleteValueW at 0x14008a000
	OpenProcessToken at 0x14008a008
	LookupPrivilegeValueW at 0x14008a010
	AdjustTokenPrivileges at 0x14008a018
	InitializeSecurityDescriptor at 0x14008a020
	AllocateAndInitializeSid at 0x14008a028
	RegCloseKey at 0x14008a030
	RegQueryValueExW at 0x14008a038
	RegSetValueExW at 0x14008a040
	RegOpenKeyExA at 0x14008a048
	RegQueryValueExA at 0x14008a050
	RegCreateKeyExW at 0x14008a058
	RegOpenKeyExW at 0x14008a060
	CloseServiceHandle at 0x14008a068
	DeleteService at 0x14008a070
	ControlService at 0x14008a078
	OpenServiceW at 0x14008a080
	OpenSCManagerW at 0x14008a088
	StartServiceW at 0x14008a090
	CreateServiceW at 0x14008a098
	GetUserNameW at 0x14008a0a0
	FreeSid at 0x14008a0a8
	SetSecurityDescriptorDacl at 0x14008a0b0
	AddAccessAllowedAce at 0x14008a0b8
	InitializeAcl at 0x14008a0c0

[*] Listing all potentially interesting strings in rData: 
	00RSD PTR 
	000x%08X.aml
	19U@fffff
	f9Q@ffffffP@33333
	8cJ@33333sG@
	ccLD@333333A@
	99U@33333SS@
	8cM@33333sD@
	80K@33333sJ@
	99D@fffff
	a6B@ffffff=@
	00>@ffffff<@
	ccL:@3333338@
	004@fffff
	99/@ffffff+@333333\'@
	c0P@333333@@
	99YK@33333sI@
	99G@33333
	ccC@fffff
	001@fffff&W@
	ccLU@33333sS@
	99YD@fffff
	a6@@33333SU@
	00`R@fffff
	e6P@fffff
	e6N@33333
	00NtQuerySystemInformation
	00DwmGetWindowAttribute
	00 \t\n@
	00CoreTempUninstallCloseRequest
	00www.alcpu.com
	00/CoreTemp/coretempver.xml
	a0\t\n@
	00p\n\n@
	e8\n\n@
	08\r\n@
	80\r\n@
	00\\k\n
	00invalid string position
	00string too long
	00RightToLeft
	00Language
	00CoreTemp
	00Culture
	00Strings
	00Dialogs
	00Menus
	00Controls
	00Value
	00Caption
	00SubMenus
	00OriginalText
	00RightAlignText
	00  \n@
	00 !\n@
	00IsThemeActive
	00IsAppThemed
	00(#\n@
	00 $\n@
	00(&\n@
	00X(\n@
	00H\'\n@
	00CoreTempStartup.xml
	00p)\n@
	00GetSystemFirmwareTable
	00EnumSystemFirmwareTables
	00GetActiveProcessorGroupCount
	00GetActiveProcessorCount
	00GetSystemInfo
	00GetNativeSystemInfo
	00GetThreadGroupAffinity
	00SetThreadGroupAffinity
	00SetProcessAffinityMask
	00SetThreadAffinityMask
	00GetProcessAffinityMask
	00AdjustWindowRectExForDpi
	00SystemParametersInfoForDpi
	00GetDpiForMonitor
	00GetWindowInfo
	00ChangeWindowMessageFilter
	00ChangeWindowMessageFilterEx
	00LCIDToLocaleName
	00GlobalMemoryStatus
	00GlobalMemoryStatusEx
	00GetWindowTheme
	00GetThemeSysSize
	00FlashWindowEx
	00x+\n@
	00h,\n@
	00ReleasePlugin
	00GetPlugin
	00X-\n@
	00H.\n@
	00@/\n@
	00fffff
	0080\n@
	00HTTP/1.1 400 Bad Request
	0081\n@
	00<!--%s-->
	00&#x%02X;
	0002\n@
	00</%s>
	00%s="%s"
	00%s=\'%s\'
	0083\n@
	00<![CDATA[%s]]>\n
	00standalone="
	00standalone="%s" 
	00encoding="
	00encoding="%s" 
	00version="
	00version="%s" 
	00<?xml 
	00<![CDATA[
	00H4\n@
	00X5\n@
	00Error when TiXmlDocument added to document, because TiXmlDocument can only be at the root.
	00Error parsing CDATA.
	00Error null (0) or unexpected EOF found in input stream.
	00Error document empty.
	00Error parsing Declaration.
	00Error parsing Comment.
	00Error parsing Unknown.
	00Error reading end tag.
	00Error: empty tag.
	00Error reading Attributes.
	00Error reading Element value.
	00Failed to read Element name
	00Error parsing Element.
	00Failed to open file
	00Error
	00No error
	00&apos;
	00&quot;
	00&amp;
	00<?xml
	00UTF-8
	00standalone
	00encoding
	00version
	00CentaurHauls
	00AuthenticAMD
	00GenuineIntel
	00month
	00releaseDate
	00notes
	00changes
	00gadget
	00\r\n\r\n
	00UpdateChecker
	00HTTP/1.1 200 OK
	00GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-cache\r\nUser-Agent: CoreTemp/1.1\r\n\r\n
	00X6\n@
	00P7\n@
	00@8\n@
	0009\n@
	00 :\n@
	00 <\n@
	00failed
	00success
	07B333?o
	83<ff6?
	008>\n@
	00`>\n@
	00P?\n@
	00DPIO module
	00Performance counter
	00Communications synchronization plus time and frequency test/measurement
	00Management card
	00Data Acquisition and Signal Processing Controller
	00Network and computing Encrypt/Decrypt
	00Entertainment Encrypt/Decrypt
	00Encryption/Decryption Controller
	00Audio
	00Voice
	00Satellite Communications Controller
	00Intelligent IO controller
	00Message FIFO at offset 40h
	00Intelligent IO controller adhering to the I2O Architecture spec
	00802.11G Ethernet device
	00802.11B Ethernet device
	00802.11A Ethernet device
	00Bluetooth device
	00RF controller
	00Consumre IR controller
	00IrDA controller
	00Serial Bus Controller
	00CANbus
	00SERCOS Interface Standard
	00IPMI SMIC Interface
	00IPMI Kybd Controller Style Interface
	00IPMI Block Transfer Interface
	00IPMI Interface
	00InfiniBand
	00SMBus controller
	00Fibre channelr controller
	00USB (Universal Serial Bus) controller
	00SSA (Serial Storage Architecture) controller
	00ACCESS bus controller
	00Firewire (IEEE 1394) controller
	00Unknown Processor
	00Co-Processor
	00PowerPC Processor
	00Alpha Processor
	00Pentium Processor
	00486 Processor
	00386 Processor
	00Generic docking station
	00Unknown type of docking station
	00Keyboard controller
	00Digitizer (pen)
	00Mouse controller
	00Scanner controller
	00Gameport controller
	00Generic input controller
	00Generic 8259 PIC
	00ISA PIC
	00EISA PIC
	00I/O APIC Interrupt Controller
	00Peripheral Controller
	00ISA DMA controller
	00EISA DMA controller
	00Generic 8237 DMA controller
	00ISA system timer
	00EISA system timer
	00High Performance Event timer
	00Generic 8254 timer
	00ISA RTC controller
	00Generic RTC controller
	00Generic PCI Hot-Plug controller
	00Generic system peripheral
	00Simple Communications Controller
	00Smart Card controller
	00GPIB (IEEE 488.1/2) controller
	00Modem controller
	00Multi port serial controller
	00Bi-directional parallel port
	00ECP 1.X parallel port
	00IEEE 1284 controller
	00IEEE 1284 target device
	00Parallel port
	00Generic XT compatible serial controller
	0016950 compatible serial controller
	0016850 compatible serial controller
	0016750 compatible serial controller
	0016650 compatible serial controller
	0016550 compatible serial controller
	0016450 compatible serial controller
	00Unknown bridge type
	00Custom interface
	00ASI-SIG Portal Interface
	00PCI to AS bridge
	00PCI to InfiniBand bridge
	00PCI to Raceway bridge
	00PCI to CardBus bridge
	00PCI to NuBus bridge
	00PCI to PCMCIA bridge
	00PCI to PCI bridge
	00PCI to Micro Channel bridge
	00PCI to EISA bridge
	00PCI to ISA bridge
	00Host to PCI bridge
	00RAM controller
	00Flash memory controller
	00Memory controller
	00Video device
	00Audio device
	00Telephony device
	00HD Audio device
	00Multimedia device
	00VGA display controller
	008514 display controller
	00XGA display controller
	003D display controller
	00Display controller
	00Network controller
	00PICMG 2.14 Multi Computing
	00WorldFip controller
	00ISDN controller
	00ATM controller
	00FDDI controller
	00Token ring
	00Ethernet controller
	00Mass Storage Controller
	00Serial Attached SCSI controller
	00SATA controller
	00ATA controller
	00RAID controller
	00IPI controller
	00Floppy disk controller
	00IDE controller
	00SCSI controller
	00VGA device
	00%s\\pcidevs.txt
	00Unknown
	00@@\n@
	008A\n@
	00bad allocation
	00Access violation - no RTTI data!
	00Bad dynamic_cast!
	00Unknown exception
	008C\n@
	00(null)
	00( 8PX
	00700WP
	08`h````
	00xpxxxx
	00CorExitProcess
	00(\'8PW
	00700PP
	00`h`hhh
	07xppwpp
	00@D\n@
	00bad exception
	00e+000
	00SunMonTueWedThuFriSat
	00JanFebMarAprMayJunJulAugSepOctNovDec
	00HH:mm:ss
	00dddd, MMMM dd, yyyy
	00MM/dd/yy
	00December
	00November
	00October
	00September
	00August
	00April
	00March
	00February
	00January
	00Saturday
	00Friday
	00Thursday
	00Wednesday
	00Tuesday
	00Monday
	00Sunday
	1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~
	00UTF-8
	00UTF-16LE
	00UNICODE
	00 Complete Object Locator\'
	00 Class Hierarchy Descriptor\'
	00 Base Class Array\'
	00 Base Class Descriptor at (
	00 Type Descriptor\'
	00`local static thread guard\'
	00`managed vector copy constructor iterator\'
	00`vector vbase copy constructor iterator\'
	00`vector copy constructor iterator\'
	00`dynamic atexit destructor for \'
	00`dynamic initializer for \'
	00`eh vector vbase copy constructor iterator\'
	00`eh vector copy constructor iterator\'
	00`managed vector destructor iterator\'
	00`managed vector constructor iterator\'
	00`placement delete[] closure\'
	00`placement delete closure\'
	00`omni callsig\'
	00 delete[]
	00 new[]
	00`local vftable constructor closure\'
	00`local vftable\'
	00`RTTI
	00`udt returning\'
	00`copy constructor closure\'
	00`eh vector vbase constructor iterator\'
	00`eh vector destructor iterator\'
	00`eh vector constructor iterator\'
	00`virtual displacement map\'
	00`vector vbase constructor iterator\'
	00`vector destructor iterator\'
	00`vector constructor iterator\'
	00`scalar deleting destructor\'
	00`default constructor closure\'
	00`vector deleting destructor\'
	00`vbase destructor\'
	00`string\'
	00`local static guard\'
	00`typeof\'
	00`vcall\'
	00`vbtable\'
	00`vftable\'
	00operator
	00 delete
	00__unaligned
	00__restrict
	00__ptr64
	00__eabi
	00__clrcall
	00__fastcall
	00__thiscall
	00__stdcall
	00__pascal
	00__cdecl
	00__based(
	00GetProcessWindowStation
	00GetUserObjectInformationW
	00GetLastActivePopup
	00GetActiveWindow
	00MessageBoxW
	1f !"#$%&\'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~
	1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~
	001#QNAN
	001#INF
	001#IND
	001#SNAN
	00@E\n@
	cc\t6:fJ
	83!Q\t@
	83NKagj(h
	a4Mb=Lk
	90NSOFTWARE\\Classes\\CLSID\\{FE750200-B72E-11d9-829B-0050DA1A72D3}\\ServerBinary
	00GetInterface
	00RSDSu
	00F:\\Programming\\CoreTemp\\CoreTemp\
	64\\Release\\Core Temp.pdb
	00H\t\n
	00 \t\n
	00`\t\n
	00x\t\n
	00H\t\n
	00 \n\n
	00H\n\n
	00`\n\n
	00 \n\n
	00p\n\n
	000\r\n
	00H\r\n
	00X\r\n
	000\r\n
	00 \'\n
	00p\'\n
	00H\'\n
	00p\'\n
	00p\'\n
	00 \n\n
	00H\n\n
	00 \n\n
	00 \n\n
	00\n4\n
	00\n4\n
	00\n4\n
	00\n4\n
	00\nT\n
	00\\O\n
	00\\O\n
	00\n4\r
	00\nd\n
	00\n4\n
	00\n4\r
	00\rr\t
	00\r4\n
	00\nd\t
	00\r4\t
	00\rT\'
	0e !4\r !
	00?t1@7d0@/4/@
	0e2\np!
	0e2\np!
	00\nt\t
	00\nT\t
	00\nT\t
	00\n4\r
	00\rT\n
	00\r2\t
	00\rR\t
	00\rr\t
	00\rR\t
	00\n4\n
	00\n4\t
	00\rb\t
	00\nt\t
	00\nd\n
	00\nd\t
	00\nt\t
	00\n4\n
	00\nd\t
	00\nT\t
	00\rr\t
	00\rt\n
	0bp!"\n
	00\r4\n
	00\r2\t
	d2\np\t`
	00\n4\n
	00\n4\n
	00InitCommonControlsEx
	00ImageList_Destroy
	00ImageList_GetIcon
	00ImageList_AddMasked
	00ImageList_Create
	00COMCTL32.dll
	00SetSuspendState
	00POWRPROF.dll
	00GdipFree
	00GdipAlloc
	01GdipLoadImageFromFile
	00GdipDisposeImage
	01GdipSaveImageToFile
	01GdipGetImageWidth
	01GdipGetImageEncodersSize
	01GdipGetImageEncoders
	00GdipCloneImage
	02GdiplusShutdown
	02GdiplusStartup
	00gdiplus.dll
	02GetLastError
	03MulDiv
	04Sleep
	02GetModuleFileNameW
	02GetTickCount
	02GetLocalTime
	02GetVersionExW
	02GetProcAddress
	02GetModuleHandleW
	04VerifyVersionInfoW
	04VerSetConditionMask
	00CloseHandle
	03ReleaseMutex
	03OpenMutexW
	00DeleteFileW
	05WriteFile
	00CreateFileW
	03MapViewOfFile
	00CreateFileMappingW
	05WaitForSingleObject
	00CreateMutexW
	04UnmapViewOfFile
	03LocalFree
	01FormatMessageW
	01GetDateFormatW
	01GetCurrentProcess
	01GetCurrentThread
	00CreateThread
	01GetExitCodeThread
	02GetFullPathNameW
	01GetFileSizeEx
	01FindClose
	01FindFirstFileW
	03MultiByteToWideChar
	05WideCharToMultiByte
	00DeviceIoControl
	01FindNextFileW
	01FreeResource
	03LockResource
	03LoadResource
	01FindResourceW
	01EnumResourceNamesW
	02GetUserDefaultUILanguage
	03QueryPerformanceFrequency
	03QueryPerformanceCounter
	03LocalAlloc
	05lstrcpynW
	01FreeLibrary
	03LoadLibraryW
	01GetFileSize
	04TerminateThread
	04SetErrorMode
	04SetFileAttributesW
	04RemoveDirectoryW
	04SetThreadPriority
	04SetPriorityClass
	05WaitForMultipleObjects
	03ReadFile
	02GetModuleFileNameA
	02GetVersion
	00KERNEL32.dll
	01GetSystemMetrics
	02MonitorFromPoint
	02ReleaseDC
	01GetDC
	00CallWindowProcW
	01GetWindowLongPtrW
	01GetSysColor
	02MessageBoxW
	02SetWindowPos
	02MapWindowPoints
	01GetParent
	01GetWindowRect
	02SetCursor
	01LoadCursorW
	02ShowWindow
	01InvalidateRect
	02SendMessageW
	01LoadBitmapW
	03UpdateWindow
	02SetForegroundWindow
	00CreateWindowExW
	00DestroyMenu
	02TrackPopupMenu
	01GetCursorPos
	00CheckMenuItem
	01InsertMenuItemW
	01GetMenuItemCount
	00CreatePopupMenu
	02SetWindowTextW
	02SetWindowLongPtrW
	00EndDialog
	01GetDlgItem
	02MoveWindow
	01GetClientRect
	01GetWindowTextW
	00EnableWindow
	02SendNotifyMessageW
	00EnumChildWindows
	01GetWindowLongW
	01KillTimer
	02SetTimer
	02SetWindowLongW
	01GetMenu
	01GetMenuState
	00EnableMenuItem
	00DialogBoxParamW
	00DestroyWindow
	02PostQuitMessage
	01GetSubMenu
	00DefWindowProcW
	02RegisterWindowMessageW
	02RegisterWindowMessageA
	02RegisterClassExW
	01LoadIconW
	00DispatchMessageW
	03TranslateMessage
	03TranslateAcceleratorW
	01GetMessageW
	02PostMessageW
	01IsIconic
	00FindWindowW
	01LoadAcceleratorsW
	01LoadStringW
	00CreateDialogParamW
	02ScreenToClient
	02SetMenuItemInfoW
	01GetMenuStringW
	01GetMenuItemInfoW
	01GetClassNameW
	00DrawMenuBar
	01LoadMenuW
	01GetClassInfoExW
	01GetDlgCtrlID
	01GetSysColorBrush
	00CopyRect
	02OffsetRect
	02MapDialogRect
	02SetRectEmpty
	01GetDialogBaseUnits
	02SetFocus
	00DestroyIcon
	00FillRect
	00AdjustWindowRectEx
	02SystemParametersInfoW
	00DrawTextExW
	00ExitWindowsEx
	00USER32.dll
	01GetDeviceCaps
	02SetBkColor
	02SetTextColor
	00DeleteDC
	00DeleteObject
	00BitBlt
	02SelectObject
	00CreateCompatibleDC
	00CreateSolidBrush
	00CreateDIBSection
	00CreateFontIndirectW
	02GetTextMetricsW
	02GetTextExtentPoint32W
	00CreateFontW
	02TextOutW
	02SetTextAlign
	00CreateBrushIndirect
	00CreateBitmap
	00GDI32.dll
	00GetSaveFileNameW
	00ChooseColorW
	00ChooseFontW
	00GetOpenFileNameW
	00COMDLG32.dll
	02RegCloseKey
	02RegDeleteValueW
	02RegQueryValueExW
	02RegSetValueExW
	02RegCreateKeyExW
	02RegOpenKeyExW
	00CloseServiceHandle
	00DeleteService
	00ControlService
	01OpenServiceW
	01OpenSCManagerW
	02StartServiceW
	00CreateServiceW
	01GetUserNameW
	01FreeSid
	02SetSecurityDescriptorDacl
	00AddAccessAllowedAce
	01InitializeAcl
	00AllocateAndInitializeSid
	01InitializeSecurityDescriptor
	00AdjustTokenPrivileges
	01LookupPrivilegeValueW
	01OpenProcessToken
	00ADVAPI32.dll
	01ShellExecuteW
	01Shell_NotifyIconW
	00ExtractIconW
	00SHELL32.dll
	00CoCreateInstance
	00CoInitialize
	00ole32.dll
	00OLEAUT32.dll
	00PathAppendW
	00PathRemoveFileSpecW
	00PathIsFileSpecW
	00SHLWAPI.dll
	01SetupDiDestroyDeviceInfoList
	01SetupDiGetDeviceRegistryPropertyW
	01SetupDiEnumDeviceInfo
	01SetupDiGetClassDevsW
	00SETUPAPI.dll
	00WS2_32.dll
	00VerQueryValueW
	00GetFileVersionInfoW
	00GetFileVersionInfoSizeW
	00VERSION.dll
	02HeapAlloc
	04RtlLookupFunctionEntry
	04RtlUnwindEx
	02GetSystemTimeAsFileTime
	00DecodePointer
	00EncodePointer
	02GetTimeFormatW
	02HeapFree
	03RaiseException
	04RtlPcToFileHeader
	00DeleteFileA
	01GetCommandLineW
	02GetStartupInfoW
	04UnhandledExceptionFilter
	04SetUnhandledExceptionFilter
	03IsDebuggerPresent
	04RtlVirtualUnwind
	04RtlCaptureContext
	04TerminateProcess
	01ExitProcess
	02GetStdHandle
	02HeapSetInformation
	02HeapCreate
	00EnterCriticalSection
	03LeaveCriticalSection
	01GetConsoleCP
	01GetConsoleMode
	02InitializeCriticalSectionAndSpinCount
	01FlsGetValue
	01FlsSetValue
	01FlsFree
	04SetLastError
	01GetCurrentThreadId
	01FlsAlloc
	02GetTimeZoneInformation
	01GetCPInfo
	01GetACP
	02GetOEMCP
	03IsValidCodePage
	02HeapSize
	02GetStringTypeW
	04SetHandleCount
	01GetFileType
	00DeleteCriticalSection
	04SetFilePointer
	03LCMapStringW
	01FreeEnvironmentStringsW
	01GetEnvironmentStringsW
	01GetCurrentProcessId
	04SetStdHandle
	01FlushFileBuffers
	05WriteConsoleW
	02HeapReAlloc
	00CreateFileA
	00CompareStringW
	04SetEnvironmentVariableW
	04SetEndOfFile
	02GetProcessHeap
	04SetEnvironmentVariableA
	03LoadLibraryA
	02RegQueryValueExA
	02RegOpenKeyExA

Would you like to change the compile time?
Enter y for yes: n


[*] EXE Found: unins000.exe

[*] Virus Total Scan Link:
{'scan_id': 'f515206b2c2fd3a59cf6f003143efca98456e2bdc4b7a8f622beb98f735cf667-1585622276', 'sha1': '829ce1bff9e986bfe900d656d077471b45bf810c', 'resource': 'f515206b2c2fd3a59cf6f003143efca98456e2bdc4b7a8f622beb98f735cf667', 'response_code': 1, 'sha256': 'f515206b2c2fd3a59cf6f003143efca98456e2bdc4b7a8f622beb98f735cf667', 'permalink': 'https://www.virustotal.com/file/f515206b2c2fd3a59cf6f003143efca98456e2bdc4b7a8f622beb98f735cf667/analysis/1585622276/', 'md5': 'e535020eb53af0a8cc69fd8180f7275e', 'verbose_msg': 'Scan request successfully queued, come back later for the report'}

[*] Compile Time: 2018-06-14 07:27:46

[*] File is Likely packed 

[*] Listing imported DLLs...
	oleaut32.dll
	advapi32.dll
	user32.dll
	kernel32.dll
	kernel32.dll
	user32.dll
	msimg32.dll
	gdi32.dll
	version.dll
	mpr.dll
	kernel32.dll
	advapi32.dll
	comctl32.dll
	kernel32.dll
	oleaut32.dll
	ole32.dll
	oleaut32.dll
	comctl32.dll
	shell32.dll
	shell32.dll
	comdlg32.dll
	ole32.dll
	advapi32.dll
	oleaut32.dll

[*] Advapi32.dll imports:
	RegQueryValueExW at 0x0050ea90
	RegOpenKeyExW at 0x0050ea94
	RegCloseKey at 0x0050ea98

[*] Kernel32.dll imports:
	GetACP at 0x0050eab4
	Sleep at 0x0050eab8
	VirtualFree at 0x0050eabc
	VirtualAlloc at 0x0050eac0
	GetSystemInfo at 0x0050eac4
	GetTickCount at 0x0050eac8
	QueryPerformanceCounter at 0x0050eacc
	GetVersion at 0x0050ead0
	GetCurrentThreadId at 0x0050ead4
	VirtualQuery at 0x0050ead8
	WideCharToMultiByte at 0x0050eadc
	SetCurrentDirectoryW at 0x0050eae0
	MultiByteToWideChar at 0x0050eae4
	lstrlenW at 0x0050eae8
	lstrcpynW at 0x0050eaec
	LoadLibraryExW at 0x0050eaf0
	GetThreadLocale at 0x0050eaf4
	GetStartupInfoA at 0x0050eaf8
	GetProcAddress at 0x0050eafc
	GetModuleHandleW at 0x0050eb00
	GetModuleFileNameW at 0x0050eb04
	GetLocaleInfoW at 0x0050eb08
	GetCurrentDirectoryW at 0x0050eb0c
	GetCommandLineW at 0x0050eb10
	FreeLibrary at 0x0050eb14
	FindFirstFileW at 0x0050eb18
	FindClose at 0x0050eb1c
	ExitProcess at 0x0050eb20
	ExitThread at 0x0050eb24
	CreateThread at 0x0050eb28
	CompareStringW at 0x0050eb2c
	WriteFile at 0x0050eb30
	UnhandledExceptionFilter at 0x0050eb34
	RtlUnwind at 0x0050eb38
	RaiseException at 0x0050eb3c
	GetStdHandle at 0x0050eb40
	CloseHandle at 0x0050eb44

[*] Kernel32.dll imports:
	TlsSetValue at 0x0050eb4c
	TlsGetValue at 0x0050eb50
	LocalAlloc at 0x0050eb54
	GetModuleHandleW at 0x0050eb58

[*] Kernel32.dll imports:
	lstrcpyW at 0x0050ef80
	lstrcmpW at 0x0050ef84
	WriteProfileStringW at 0x0050ef88
	WritePrivateProfileStringW at 0x0050ef8c
	WriteFile at 0x0050ef90
	WideCharToMultiByte at 0x0050ef94
	WaitForSingleObject at 0x0050ef98
	WaitForMultipleObjectsEx at 0x0050ef9c
	VirtualQueryEx at 0x0050efa0
	VirtualQuery at 0x0050efa4
	VirtualFree at 0x0050efa8
	VirtualAlloc at 0x0050efac
	TransactNamedPipe at 0x0050efb0
	TerminateProcess at 0x0050efb4
	SwitchToThread at 0x0050efb8
	SizeofResource at 0x0050efbc
	SignalObjectAndWait at 0x0050efc0
	SetThreadLocale at 0x0050efc4
	SetNamedPipeHandleState at 0x0050efc8
	SetLastError at 0x0050efcc
	SetFileTime at 0x0050efd0
	SetFilePointer at 0x0050efd4
	SetFileAttributesW at 0x0050efd8
	SetEvent at 0x0050efdc
	SetErrorMode at 0x0050efe0
	SetEndOfFile at 0x0050efe4
	SetCurrentDirectoryW at 0x0050efe8
	ResumeThread at 0x0050efec
	ResetEvent at 0x0050eff0
	RemoveDirectoryW at 0x0050eff4
	ReleaseMutex at 0x0050eff8
	ReadFile at 0x0050effc
	QueryPerformanceCounter at 0x0050f000
	OpenProcess at 0x0050f004
	OpenMutexW at 0x0050f008
	MultiByteToWideChar at 0x0050f00c
	MulDiv at 0x0050f010
	MoveFileExW at 0x0050f014
	MoveFileW at 0x0050f018
	LockResource at 0x0050f01c
	LocalFree at 0x0050f020
	LocalFileTimeToFileTime at 0x0050f024
	LoadResource at 0x0050f028
	LoadLibraryExW at 0x0050f02c
	LoadLibraryW at 0x0050f030
	LeaveCriticalSection at 0x0050f034
	IsDBCSLeadByte at 0x0050f038
	IsBadWritePtr at 0x0050f03c
	InitializeCriticalSection at 0x0050f040
	GlobalFindAtomW at 0x0050f044
	GlobalDeleteAtom at 0x0050f048
	GlobalAddAtomW at 0x0050f04c
	GetWindowsDirectoryW at 0x0050f050
	GetVersionExW at 0x0050f054
	GetVersion at 0x0050f058
	GetUserDefaultLangID at 0x0050f05c
	GetTickCount at 0x0050f060
	GetThreadLocale at 0x0050f064
	GetSystemTimeAsFileTime at 0x0050f068
	GetSystemInfo at 0x0050f06c
	GetSystemDirectoryW at 0x0050f070
	GetStdHandle at 0x0050f074
	GetShortPathNameW at 0x0050f078
	GetProfileStringW at 0x0050f07c
	GetProcAddress at 0x0050f080
	GetPrivateProfileStringW at 0x0050f084
	GetOverlappedResult at 0x0050f088
	GetModuleHandleW at 0x0050f08c
	GetModuleFileNameW at 0x0050f090
	GetLogicalDrives at 0x0050f094
	GetLocaleInfoW at 0x0050f098
	GetLocalTime at 0x0050f09c
	GetLastError at 0x0050f0a0
	GetFullPathNameW at 0x0050f0a4
	GetFileSize at 0x0050f0a8
	GetFileAttributesW at 0x0050f0ac
	GetExitCodeThread at 0x0050f0b0
	GetExitCodeProcess at 0x0050f0b4
	GetEnvironmentVariableW at 0x0050f0b8
	GetDriveTypeW at 0x0050f0bc
	GetDiskFreeSpaceW at 0x0050f0c0
	GetDateFormatW at 0x0050f0c4
	GetCurrentThreadId at 0x0050f0c8
	GetCurrentThread at 0x0050f0cc
	GetCurrentProcessId at 0x0050f0d0
	GetCurrentProcess at 0x0050f0d4
	GetCurrentDirectoryW at 0x0050f0d8
	GetComputerNameW at 0x0050f0dc
	GetCommandLineW at 0x0050f0e0
	GetCPInfo at 0x0050f0e4
	FreeResource at 0x0050f0e8
	InterlockedIncrement at 0x0050f0ec
	InterlockedExchangeAdd at 0x0050f0f0
	InterlockedExchange at 0x0050f0f4
	InterlockedDecrement at 0x0050f0f8
	InterlockedCompareExchange at 0x0050f0fc
	FreeLibrary at 0x0050f100
	FormatMessageW at 0x0050f104
	FlushFileBuffers at 0x0050f108
	FindResourceW at 0x0050f10c
	FindNextFileW at 0x0050f110
	FindFirstFileW at 0x0050f114
	FindClose at 0x0050f118
	FileTimeToSystemTime at 0x0050f11c
	FileTimeToLocalFileTime at 0x0050f120
	EnumCalendarInfoW at 0x0050f124
	EnterCriticalSection at 0x0050f128
	DeviceIoControl at 0x0050f12c
	DeleteFileW at 0x0050f130
	DeleteCriticalSection at 0x0050f134
	CreateThread at 0x0050f138
	CreateProcessW at 0x0050f13c
	CreateNamedPipeW at 0x0050f140
	CreateMutexW at 0x0050f144
	CreateFileW at 0x0050f148
	CreateEventW at 0x0050f14c
	CreateDirectoryW at 0x0050f150
	CopyFileW at 0x0050f154
	CompareStringW at 0x0050f158
	CompareFileTime at 0x0050f15c
	CloseHandle at 0x0050f160

[*] Advapi32.dll imports:
	SetSecurityDescriptorDacl at 0x0050f168
	RegSetValueExW at 0x0050f16c
	RegQueryValueExW at 0x0050f170
	RegQueryInfoKeyW at 0x0050f174
	RegOpenKeyExW at 0x0050f178
	RegFlushKey at 0x0050f17c
	RegEnumValueW at 0x0050f180
	RegEnumKeyExW at 0x0050f184
	RegDeleteValueW at 0x0050f188
	RegDeleteKeyW at 0x0050f18c
	RegCreateKeyExW at 0x0050f190
	RegCloseKey at 0x0050f194
	OpenThreadToken at 0x0050f198
	OpenProcessToken at 0x0050f19c
	LookupPrivilegeValueW at 0x0050f1a0
	InitializeSecurityDescriptor at 0x0050f1a4
	GetUserNameW at 0x0050f1a8
	GetTokenInformation at 0x0050f1ac
	FreeSid at 0x0050f1b0
	EqualSid at 0x0050f1b4
	AllocateAndInitializeSid at 0x0050f1b8

[*] Kernel32.dll imports:
	Sleep at 0x0050f1c8

[*] Advapi32.dll imports:
	AdjustTokenPrivileges at 0x0050f2fc

[*] Listing all potentially interesting strings in rData: 
	00SetDefaultDllDirectories
	00SetDllDirectoryW
	00SetSearchPathMode
	00SetProcessDEPPolicy
	c0UhC P
	c0Uh%!P
	01s,hP#P
	c0Uh\n%P
	c0UhS&P
	8b\r@[P
	c0Uh%\'P

Would you like to change the compile time?
Enter y for yes: n

[*] Directory contains no untested executables

Process finished with exit code 0


