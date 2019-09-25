public Function ExtractConfigurationFiles()
	destFolder = "C:\Program Files (x86)\ossec-agent\"
	ExtractFiles(destFolder)
	ExtractConfigurationFiles = 0
End Function


public Function ExtractSCAFiles()
	destFolder = "C:\Program Files (x86)\ossec-agent\ruleset\sca\"
	ExtractFiles(destFolder)
	ExtractSCAFiles = 0
End Function

private Function ExtractFiles(destFolder)
	On Error Resume Next
	Set fso = CreateObject("Scripting.FileSystemObject")
	If Not fso.fileExists(destFolder & "test.txt") Then
		fso.CreateTextFile destFolder & "test.txt", True
	End If
			
	Set mylog = fso.OpenTextFile(destFolder & "test.txt", 2, 0)
	mylog.Write "Start to read the directory" & vbCrLf
	set objFolder = fso.GetFolder(destFolder)

	Set objShell = CreateObject("Shell.Application")

	Set colFiles = objFolder.Files
	For Each objFile in colFiles
		mylog.Write "File inside the dir: " & objFile.Name & vbCrLf
		if instr(objFile.Name,".zip") <> 0 then
			zipFile = destFolder & objFile.Name
			mylog.Write "|" & vbCrLf
			mylog.Write "·---------> This File is a zip" & vbCrLf
			Set FilesInZip = objShell.NameSpace(zipFile).Items()
			objShell.NameSpace(destFolder).copyHere FilesInZip, 16
	        fso.DeleteFile zipFile
			Set FilesInZip = Nothing
	    end if
	Next
	
	Set fso = Nothing
	Set objShell = Nothing
	Set FilesInZip = Nothing
	Set colFiles = Nothing
End Function