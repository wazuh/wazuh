On Error Resume Next

home_dir = Replace(WScript.Arguments.Item(1), Chr(34), "")

mySubOrFuncName = WScript.Arguments.Item(0)  'name of the subroutine or function
subCall = "call " & mySubOrFuncName & "()"
Execute subCall

public Function ExtractConfigurationFiles()
	destFolder = home_dir
	ExtractFiles(destFolder)
	ExtractConfigurationFiles = 0
End Function


public Function ExtractSCAFiles()
	destFolder = home_dir & "ruleset\sca\"
	ExtractFiles(destFolder)
	ExtractSCAFiles = 0
End Function

private Function ExtractFiles(destFolder)
	Set fso = CreateObject("Scripting.FileSystemObject")
	set objFolder = fso.GetFolder(destFolder)
	Set objShell = CreateObject("Shell.Application")

	Set colFiles = objFolder.Files
	For Each objFile in colFiles
		if instr(objFile.Name,".zip") <> 0 then
			zipFile = destFolder & objFile.Name
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