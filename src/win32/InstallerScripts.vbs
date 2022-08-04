
' Script for configuration Windows agent.
' Copyright (C) 2015, Wazuh Inc. <support@wazuh.com>
'
' This program is free software; you can redistribute it and/or modify
' it under the terms of the GNU General Public License as published by
' the Free Software Foundation; either version 3 of the License, or
' (at your option) any later version.
'
' This program is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' GNU General Public License for more details.
'
' You should have received a copy of the GNU General Public License
' along with this program; if not, write to the Free Software Foundation,
' Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
'
' ------------------------------------------------'

On Error Resume Next

public function config()

Const ForReading = 1
Const ForWriting = 2

' Custom parameters
strArgs = Session.Property("CustomActionData")
args = Split(strArgs, "/+/")

home_dir= Replace(args(0), Chr(34), "")
WAZUH_MANAGER = Replace(args(1), Chr(34), "")
WAZUH_MANAGER_PORT = Replace(args(2), Chr(34), "")
WAZUH_PROTOCOL = Replace(args(3), Chr(34), "")
NOTIFY_TIME = Replace(args(4), Chr(34), "")
WAZUH_REGISTRATION_SERVER = Replace(args(5), Chr(34), "")
WAZUH_REGISTRATION_PORT = Replace(args(6), Chr(34), "")
WAZUH_REGISTRATION_PASSWORD = Replace(args(7), Chr(34), "")
WAZUH_KEEP_ALIVE_INTERVAL = Replace(args(8), Chr(34), "")
WAZUH_TIME_RECONNECT = Replace(args(9), Chr(34), "")
WAZUH_REGISTRATION_CA = Replace(args(10), Chr(34), "")
WAZUH_REGISTRATION_CERTIFICATE = Replace(args(11), Chr(34), "")
WAZUH_REGISTRATION_KEY = Replace(args(12), Chr(34), "")
WAZUH_AGENT_NAME = Replace(args(13), Chr(34), "")
WAZUH_AGENT_GROUP = Replace(args(14), Chr(34), "")
ENROLLMENT_DELAY = Replace(args(15), Chr(34), "")

' Only try to set the configuration if variables are setted

Set objFSO = CreateObject("Scripting.FileSystemObject")

' Create an empty client.keys file on first install
If Not objFSO.fileExists(home_dir & "client.keys") Then
    objFSO.CreateTextFile(home_dir & "client.keys")
End If

If objFSO.fileExists(home_dir & "ossec.conf") Then
    ' Reading ossec.conf file
    Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForReading)

    strText = objFile.ReadAll
    objFile.Close

    If WAZUH_MANAGER <> "" or WAZUH_MANAGER_PORT <> "" or WAZUH_PROTOCOL <> "" or WAZUH_KEEP_ALIVE_INTERVAL <> "" or WAZUH_TIME_RECONNECT <> "" Then
        If WAZUH_MANAGER <> "" and InStr(WAZUH_MANAGER,";") > 0 Then 'list of address
            ip_list=Split(WAZUH_MANAGER,";")
            formatted_list ="    </server>" & vbCrLf
            not_replaced = True
            for each ip in ip_list
                If not_replaced Then
                    strText = Replace(strText, "<address>0.0.0.0</address>", "<address>" & ip & "</address>")
                    not_replaced = False
                Else
                    formatted_list = formatted_list & "    <server>" & vbCrLf
                    formatted_list = formatted_list & "      <address>" & ip & "</address>" & vbCrLf
                    formatted_list = formatted_list & "      <port>1514</port>" & vbCrLf
                    formatted_list = formatted_list & "      <protocol>tcp</protocol>" & vbCrLf
                    formatted_list = formatted_list & "    </server>" & vbCrLf
                End If
            next
            strText = Replace(strText, "    </server>", formatted_list)
        ElseIf WAZUH_MANAGER <> "" and InStr(strText,"<address>") > 0 Then
            strText = Replace(strText, "<address>0.0.0.0</address>", "<address>" & WAZUH_MANAGER & "</address>")

        ElseIf WAZUH_MANAGER <> "" Then 'single address
            ' Fix for the legacy server-ip and server-hostname keynames
            Set re = new regexp
            re.Pattern = "<server-ip>.*</server-ip>"
            re.Global = True
            strText = re.Replace(strText, "<server-ip>" & WAZUH_MANAGER & "</server-ip>")
            re.Pattern = "<server-hostname>.*</server-hostname>"
            re.Global = True
            strText = re.Replace(strText, "<server-hostname>" & WAZUH_MANAGER & "</server-hostname>")
            strText = Replace(strText, "<address>0.0.0.0</address>", "<address>" & WAZUH_MANAGER & "</address>")
        End If

        If WAZUH_MANAGER_PORT <> "" Then ' manager server_port
            If InStr(strText, "<port>") > 0 Then
                strText = Replace(strText, "<port>1514</port>", "<port>" & WAZUH_MANAGER_PORT & "</port>")
            Else
                ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "  <port>" & WAZUH_MANAGER_PORT & "</port>"& vbCrLf &"  </client>")
            End If

        End If

        If WAZUH_PROTOCOL <> "" Then
            If InStr(strText, "<protocol>") > 0 Then
                Set re = new regexp
                re.Pattern = "<protocol>.*</protocol>"
                re.Global = True
                strText = re.Replace(strText, "<protocol>" & LCase(WAZUH_PROTOCOL) & "</protocol>")
            Else
            ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "   <protocol>" & LCase(WAZUH_PROTOCOL) & "</protocol>"& vbCrLf &"  </client>")
            End If
        End If

        If WAZUH_KEEP_ALIVE_INTERVAL <> "" Then
            If InStr(strText, "<notify_time>") > 0 Then
                Set re = new regexp
                re.Pattern = "<notify_time>.*</notify_time>"
                re.Global = True
                strText = re.Replace(strText, "<notify_time>" & WAZUH_KEEP_ALIVE_INTERVAL & "</notify_time>")
            Else
                ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "   <notify_time>" & WAZUH_KEEP_ALIVE_INTERVAL & "</notify_time>"& vbCrLf &"  </client>")
            End If
        End If

        If WAZUH_TIME_RECONNECT <> "" Then 'TODO fix the - and use _
            If InStr(strText, "<time-reconnect>") > 0 Then
                Set re = new regexp
                re.Pattern = "<time-reconnect>.*</time-reconnect>"
                re.Global = True
                strText = re.Replace(strText, "<time-reconnect>" & WAZUH_TIME_RECONNECT & "</time-reconnect>")
            Else
                ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "   <time-reconnect>" & WAZUH_TIME_RECONNECT & "</time-reconnect>"& vbCrLf &"  </client>")

            End If
        End If

    End If
    
    If WAZUH_REGISTRATION_SERVER <> "" or WAZUH_REGISTRATION_PORT <> "" or WAZUH_REGISTRATION_PASSWORD <> "" or WAZUH_REGISTRATION_CA <> "" or WAZUH_REGISTRATION_CERTIFICATE <> "" or WAZUH_REGISTRATION_KEY <> "" or WAZUH_AGENT_NAME <> "" or WAZUH_AGENT_GROUP <> "" or ENROLLMENT_DELAY <> "" Then
        enrollment_list = "    <enrollment>" & vbCrLf
        enrollment_list = enrollment_list & "        <enabled>yes</enabled>" & vbCrLf
        enrollment_list = enrollment_list & "    </enrollment>" & vbCrLf
        enrollment_list = enrollment_list & "  </client>" & vbCrLf

        strText = Replace(strText, "  </client>", enrollment_list)

        If WAZUH_REGISTRATION_SERVER <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <manager_address>" & WAZUH_REGISTRATION_SERVER & "</manager_address>"& vbCrLf &"    </enrollment>")
        End If  
        
        If WAZUH_REGISTRATION_PORT <> "" Then
            strText = Replace(strText, "    </enrollment>", "  <port>" & WAZUH_REGISTRATION_PORT & "</port>"& vbCrLf &"    </enrollment>")
        End If
        
        If WAZUH_REGISTRATION_PASSWORD <> "" Then
            Set objFile = objFSO.CreateTextFile(home_dir & "authd.pass", ForWriting)
            objFile.WriteLine WAZUH_REGISTRATION_PASSWORD
            objFile.Close
        End If

        If WAZUH_REGISTRATION_CA <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <server_ca_path>" & WAZUH_REGISTRATION_CA & "</server_ca_path>"& vbCrLf &"    </enrollment>")
        End If

        If WAZUH_REGISTRATION_CERTIFICATE <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <agent_certificate_path>" & WAZUH_REGISTRATION_CERTIFICATE & "</agent_certificate_path>"& vbCrLf &"    </enrollment>")
        End If

        If WAZUH_REGISTRATION_KEY <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <agent_key_path>" & WAZUH_REGISTRATION_KEY & "</agent_key_path>"& vbCrLf &"    </enrollment>")
        End If

        If WAZUH_AGENT_NAME <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <agent_name>" & WAZUH_AGENT_NAME & "</agent_name>"& vbCrLf &"    </enrollment>")
        End If

        If WAZUH_AGENT_GROUP <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <groups>" & WAZUH_AGENT_GROUP & "</groups>"& vbCrLf &"    </enrollment>")
        End If

        If ENROLLMENT_DELAY <> "" Then
            strText = Replace(strText, "    </enrollment>", "        <delay_after_enrollment>" & ENROLLMENT_DELAY & "</delay_after_enrollment>"& vbCrLf &"    </enrollment>")
        End If

    End If

    ' Writing the ossec.conf file
    Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForWriting)
    objFile.WriteLine strText
    objFile.Close

    If Not objFSO.fileExists(home_dir & "local_internal_options.conf") Then

        If objFSO.fileExists(home_dir & "default-local_internal_options.conf") Then
            ' Reading default-local_internal_options.conf file
            Set objFile = objFSO.OpenTextFile(home_dir & "default-local_internal_options.conf", ForReading)
            strText = objFile.ReadAll
            objFile.Close

            ' Writing the local_internal_options.conf file
            Set objFile = objFSO.CreateTextFile(home_dir & "local_internal_options.conf", ForWriting)
            objFile.WriteLine strText
            objFile.Close
        Else
            Set objFile = objFSO.CreateTextFile(home_dir & "local_internal_options.conf", ForWriting)
            objFile.WriteLine("# local_internal_options.conf")
            objFile.WriteLine("#")
            objFile.WriteLine("# This file should be handled with care. It contains")
            objFile.WriteLine("# run time modifications that can affect the use")
            objFile.WriteLine("# of OSSEC. Only change it if you know what you")
            objFile.WriteLine("# are doing. Look first at ossec.conf")
            objFile.WriteLine("# for most of the things you want to change.")
            objFile.WriteLine("#")
            objFile.WriteLine("# This file will not be overwritten during upgrades")
            objFile.WriteLine("# but will be removed when the agent is un-installed.")
            objFile.Close
        End If

    End If

End If

    ' Replace templates
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

    If objFSO.fileExists(home_dir & "wodle-syscollector.template") Then
        Set file = objFSO.OpenTextFile(home_dir & "wodle-syscollector.template", ForReading)
        newline = file.ReadAll
        file.Close
        re.Pattern = "  <wodle name=""syscollector"">(" & vbCrLf & "(.*))*</processes>\s*(</wodle>)?"
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
        re.Pattern = "  <localfile>" & vbCrLf	& ".*Application(.*" & vbCrLf & ")*.*Security(.*" & vbCrLf & ")*.*System.*" & vbCrLf & ".*" & vbCrLf & "  </localfile>"
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

If GetVersion() >= 6 Then
	Set WshShell = CreateObject("WScript.Shell")

	' Remove last backslash from home_dir
	install_dir = Left(home_dir, Len(home_dir) - 1)

	setPermsInherit = "icacls """ & install_dir & """ /inheritancelevel:d /q"
	WshShell.run setPermsInherit, 0, True

	remUserPerm = "icacls """ & install_dir & """ /remove *S-1-5-32-545 /q"
	WshShell.run remUserPerm, 0, True

	' Remove Everyone group for ossec.conf
	remEveryonePerms = "icacls """ & home_dir & "ossec.conf" & """ /remove *S-1-1-0 /q"
	WshShell.run remEveryonePerms, 0, True
End If

config = 0

End Function

Private Function GetVersion()
	Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
	Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem",,48)

	For Each objItem in colItems
		GetVersion = Split(objItem.Version,".")(0)
	Next
End Function

Public Function CheckSvcRunning()
	Set wmi = GetObject("winmgmts://./root/cimv2")

    SERVICE = "OssecSvc"
    Set svc = wmi.ExecQuery("Select * from Win32_Service where Name = '" & SERVICE & "'")

    If svc.Count <> 0 Then
        state = wmi.Get("Win32_Service.Name='" & SERVICE & "'").State
        Session.Property("OSSECRUNNING") = state
    End If

    SERVICE = "WazuhSvc"
    Set svc = wmi.ExecQuery("Select * from Win32_Service where Name = '" & SERVICE & "'")

    If svc.Count <> 0 Then
        state = wmi.Get("Win32_Service.Name='" & SERVICE & "'").State
        Session.Property("WAZUHRUNNING") = state
    End If

	CheckSvcRunning = 0
End Function
