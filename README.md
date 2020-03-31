# PMA_Project_1
COSC 4010 Binary Analysis Project 1

The purpose of our program is to analyze a directory of files to allow the user to potentially determine if the given files are malware. Our code goes through each .exe or .dll file in a given directory and looks for strings, lists imports, checks if the file is packed, runs the file through VirusTotal, and gets the compile time. 

For the second part of this project, we decided to change the compile time of a given file in the directory that is being searched. If the user decided to change the compile time, a new .exe will be created within the python project directory. This new file will be called new"original filename".exe. This new file still runs and functions the same as the original. This functionality allows the user to directly compare the original and new files side by side. 

Testing And Outputs

Chapter 1 Malware Directory:



Malware VM Program Files Directory:



Note: The reason no executables were tested is because our program only analyzes the directory to find executables and .dll files. There is no functionality that allows the sub directories to have their contents analyzed as well. 
