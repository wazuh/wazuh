On Error Resume Next
const ForWriting = 2
const ForReading = 1

home_dir = Replace(args(0), Chr(34), "")

Set objFSO = CreateObject("Scripting.FileSystemObject")

If objFSO.fileExists(home_dir & "ossec.conf") Then
  ' Reading ossec.conf file
  Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForReading)
  Set re = new regexp

  strNewText = objFile.ReadAll
  objFile.Close

  If objFSO.fileExists(home_dir & "profile.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "profile.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "(</server>)"
    re.Global = False
    strNewText = re.Replace(strNewText, "$1" & vbCrLf & "    " & newline)
  End If

  If objFSO.fileExists(home_dir & "header-comments.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "header-comments.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "<!--" & vbCrLf & "(.*" & vbCrLf & ")*-->"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If

  If objFSO.fileExists(home_dir & "logging.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "logging.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "  <logging>" & vbCrLf & "(.*" & vbCrLf & ")*  </logging>"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If

  If objFSO.fileExists(home_dir & "rootcheck.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "rootcheck.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "  <rootcheck>" & vbCrLf & "(.*" & vbCrLf & ")*  </rootcheck>"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If

  If objFSO.fileExists(home_dir & "wodle-openscap.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "wodle-openscap.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "  <wodle-openscap>" & vbCrLf & "(.*" & vbCrLf & ")*  </wodle-openscap>"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If

  If objFSO.fileExists(home_dir & "wodle-syscollector.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "wodle-syscollector.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "  <wodle-syscollector>" & vbCrLf & "(.*" & vbCrLf & ")*  </wodle-syscollector>"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If

  If objFSO.fileExists(home_dir & "syscheck.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "syscheck.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "  <syscheck>" & vbCrLf & "(.*" & vbCrLf & ")*  </syscheck>"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If

	If objFSO.fileExists(home_dir & "localfile-events.template") Then
	  Set file = objFSO.OpenTextFile(home_dir & "localfile-events.template", ForReading)
	  newline = file.ReadAll
	  file.Close
	  re.Pattern = "  <localfile>" & vbCrLf	& ".*Application(.*" & vbCrLf & ")*.*Security(.*" & vbCrLf & ")*.*System(.*" & vbCrLf & ")*  </localfile>"
	  re.Global = False
	  strNewText = re.Replace(strNewText, newline)
	End If

  If objFSO.fileExists(home_dir & "sca.template") Then
    Set file = objFSO.OpenTextFile(home_dir & "sca.template", ForReading)
    newline = file.ReadAll
    file.Close
    re.Pattern = "  <sca>" & vbCrLf & "(.*" & vbCrLf & ")*  </sca>"
    re.Global = False
    strNewText = re.Replace(strNewText, newline)
  End If  

  If objFSO.fileExists(home_dir & "localfile-logs.template") Then
	  Set file = objFSO.OpenTextFile(home_dir & "localfile-logs.template", ForReading)
	  newline = file.ReadAll
	  file.Close
	  re.Pattern = "(<!-- Log analysis -->\s*)"
	  re.Global = False
	  strNewText = re.Replace(strNewText, "$1" & vbCrLf & newline)
	End If

  If objFSO.fileExists(home_dir & "localfile-commands.template") Then
	  Set file = objFSO.OpenTextFile(home_dir & "localfile-commands.template", ForReading)
	  newline = file.ReadAll
	  file.Close
	  re.Pattern = "(</localfile>\s*)(  <!--)"
	  re.Global = False
	  strNewText = re.Replace(strNewText, "$1" & newline & vbCrLf & "$2")
	End If

  ' Writing the ossec.conf file
  Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForWriting)
  objFile.WriteLine strNewText
  objFile.Close

End If

