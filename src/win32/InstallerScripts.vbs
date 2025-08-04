
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

private function get_unique_array_values(array)
    Dim dicTemp : Set dicTemp = CreateObject("Scripting.Dictionary")
    Dim DicItem
    For Each DicItem In array
        dicTemp(DicItem) = 0
    Next
    get_unique_array_values = dicTemp.Keys()
End Function


public function config()

    Const ForReading = 1
    Const ForWriting = 2

    ' Custom parameters
    strArgs = Session.Property("CustomActionData")
    args = Split(strArgs, "/+/")

    home_dir= Replace(args(0), Chr(34), "")
    OS_VERSION = Replace(args(1), Chr(34), "")
    WAZUH_MANAGER = Replace(args(2), Chr(34), "")
    WAZUH_MANAGER_PORT = Replace(args(3), Chr(34), "")
    WAZUH_PROTOCOL = Replace(args(4), Chr(34), "")
    NOTIFY_TIME = Replace(args(5), Chr(34), "")
    WAZUH_REGISTRATION_SERVER = Replace(args(6), Chr(34), "")
    WAZUH_REGISTRATION_PORT = Replace(args(7), Chr(34), "")
    WAZUH_REGISTRATION_PASSWORD = Replace(args(8), Chr(34), "")
    WAZUH_KEEP_ALIVE_INTERVAL = Replace(args(9), Chr(34), "")
    WAZUH_TIME_RECONNECT = Replace(args(10), Chr(34), "")
    WAZUH_REGISTRATION_CA = Replace(args(11), Chr(34), "")
    WAZUH_REGISTRATION_CERTIFICATE = Replace(args(12), Chr(34), "")
    WAZUH_REGISTRATION_KEY = Replace(args(13), Chr(34), "")
    WAZUH_AGENT_NAME = Replace(args(14), Chr(34), "")
    WAZUH_AGENT_GROUP = Replace(args(15), Chr(34), "")
    ENROLLMENT_DELAY = Replace(args(16), Chr(34), "")

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
            If WAZUH_PROTOCOL <> "" and InStr(WAZUH_PROTOCOL,",") Then
                protocol_list=Split(LCase(WAZUH_PROTOCOL),",")
            Else
                protocol_list=Array(LCase(WAZUH_PROTOCOL))
            End If
            If WAZUH_MANAGER <> "" Then
                Set re = new regexp
                re.Pattern = "\s+<server>(.|\n)+?</server>"
                If InStr(WAZUH_MANAGER,",") Then
                    ip_list=Split(WAZUH_MANAGER,",")
                Else
                    ip_list=Array(WAZUH_MANAGER)
                End If

                unique_protocol_list=get_unique_array_values(protocol_list)

                if ( UBound(protocol_list) >= UBound(ip_list) And UBound(unique_protocol_list) = 0 ) Or (WAZUH_PROTOCOL = "") Or ( UBound(unique_protocol_list) = 0 And LCase(unique_protocol_list(0)) = "tcp" ) Then
                    ip_list=get_unique_array_values(ip_list)
                End If

                not_replaced = True
                formatted_list = vbCrLf
                for i=0 to UBound(ip_list)
                    If ip_list(i) <> "" Then
                        formatted_list = formatted_list & "    <server>" & vbCrLf
                        formatted_list = formatted_list & "      <address>" & ip_list(i) & "</address>" & vbCrLf
                        formatted_list = formatted_list & "      <port>1514</port>" & vbCrLf
                        if UBound(protocol_list) >= i Then
                            if protocol_list(i) <> "" Then
                                formatted_list = formatted_list & "      <protocol>" & LCase(protocol_list(i)) & "</protocol>" & vbCrLf
                            Else
                                formatted_list = formatted_list & "      <protocol>tcp</protocol>" & vbCrLf
                            End If
                        Else
                            formatted_list = formatted_list & "      <protocol>tcp</protocol>" & vbCrLf
                        End If
                        if i = UBound(ip_list) then
                            formatted_list = formatted_list & "    </server>"
                        Else
                            formatted_list = formatted_list & "    </server>" & vbCrLf
                        End If
                    End If
                next
                strText = re.Replace(strText, formatted_list)
            Else
                If WAZUH_PROTOCOL <> "" Then
                    Set re = new regexp
                    re.Pattern = "<protocol>.*</protocol>"
                    strText = re.Replace(strText, "      <protocol>" & LCase(protocol_list(0)) & "</protocol>")
                End If
            End If

            If WAZUH_MANAGER_PORT <> "" Then ' manager server_port
                If InStr(strText, "<port>") > 0 Then
                    strText = Replace(strText, "<port>1514</port>", "<port>" & WAZUH_MANAGER_PORT & "</port>")
                End If

            End If

            If WAZUH_KEEP_ALIVE_INTERVAL <> "" Then
                If InStr(strText, "<notify_time>") > 0 Then
                    Set re = new regexp
                    re.Pattern = "<notify_time>.*</notify_time>"
                    re.Global = True
                    strText = re.Replace(strText, "<notify_time>" & WAZUH_KEEP_ALIVE_INTERVAL & "</notify_time>")
                End If
            End If

            If WAZUH_TIME_RECONNECT <> "" Then 'TODO fix the - and use _
                If InStr(strText, "<time-reconnect>") > 0 Then
                    Set re = new regexp
                    re.Pattern = "<time-reconnect>.*</time-reconnect>"
                    re.Global = True
                    strText = re.Replace(strText, "<time-reconnect>" & WAZUH_TIME_RECONNECT & "</time-reconnect>")
                End If
            End If
        End If

        If WAZUH_REGISTRATION_SERVER <> "" or WAZUH_REGISTRATION_PORT <> "" or WAZUH_REGISTRATION_PASSWORD <> "" or WAZUH_REGISTRATION_CA <> "" or WAZUH_REGISTRATION_CERTIFICATE <> "" or WAZUH_REGISTRATION_KEY <> "" or WAZUH_AGENT_NAME <> "" or WAZUH_AGENT_GROUP <> "" or ENROLLMENT_DELAY <> "" Then
            enrollment_list = "    <enrollment>" & vbCrLf
            enrollment_list = enrollment_list & "      <enabled>yes</enabled>" & vbCrLf
            enrollment_list = enrollment_list & "    </enrollment>" & vbCrLf
            enrollment_list = enrollment_list & "  </client>" & vbCrLf

            strText = Replace(strText, "  </client>", enrollment_list)

            If WAZUH_REGISTRATION_SERVER <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <manager_address>" & WAZUH_REGISTRATION_SERVER & "</manager_address>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_REGISTRATION_PORT <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <port>" & WAZUH_REGISTRATION_PORT & "</port>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_REGISTRATION_PASSWORD <> "" Then
                Set objFile = objFSO.CreateTextFile(home_dir & "authd.pass", ForWriting)
                objFile.WriteLine WAZUH_REGISTRATION_PASSWORD
                objFile.Close
                strText = Replace(strText, "    </enrollment>", "      <authorization_pass_path>authd.pass</authorization_pass_path>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_REGISTRATION_CA <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <server_ca_path>" & WAZUH_REGISTRATION_CA & "</server_ca_path>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_REGISTRATION_CERTIFICATE <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <agent_certificate_path>" & WAZUH_REGISTRATION_CERTIFICATE & "</agent_certificate_path>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_REGISTRATION_KEY <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <agent_key_path>" & WAZUH_REGISTRATION_KEY & "</agent_key_path>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_AGENT_NAME <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <agent_name>" & WAZUH_AGENT_NAME & "</agent_name>"& vbCrLf &"    </enrollment>")
            End If

            If WAZUH_AGENT_GROUP <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <groups>" & WAZUH_AGENT_GROUP & "</groups>"& vbCrLf &"    </enrollment>")
            End If

            If ENROLLMENT_DELAY <> "" Then
                strText = Replace(strText, "    </enrollment>", "      <delay_after_enrollment>" & ENROLLMENT_DELAY & "</delay_after_enrollment>"& vbCrLf &"    </enrollment>")
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

    If objFSO.fileExists(home_dir & "profile-" & OS_VERSION & ".template") Then
        Set file = objFSO.OpenTextFile(home_dir & "profile-" & OS_VERSION & ".template", ForReading)
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

    If objFSO.fileExists(home_dir & "syscheck-" & OS_VERSION & ".template") Then
        Set file = objFSO.OpenTextFile(home_dir & "syscheck-" & OS_VERSION & ".template", ForReading)
        newline = file.ReadAll
        file.Close
        re.Pattern = "  <syscheck>" & vbCrLf & "(.*" & vbCrLf & ")*  </syscheck>"
        re.Global = False
        strNewText = re.Replace(strNewText, newline)
    End If

    If objFSO.fileExists(home_dir & "localfile-events-" & OS_VERSION & ".template") Then
        Set file = objFSO.OpenTextFile(home_dir & "localfile-events-" & OS_VERSION & ".template", ForReading)
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

    SetWazuhPermissions()

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

Public Function KillGUITask()
    Set WshShell = CreateObject("WScript.Shell")

    taskkillcommand = "taskkill.exe /f /im win32ui.exe"
    WshShell.run taskkillcommand, 0, True

End Function

Public Function StartWazuhSvc()
	Set WshShell = CreateObject("WScript.Shell")
    StartSvc = "NET START WazuhSvc"
    WshShell.run StartSvc, 0, True
End Function

Public Function SetWazuhPermissions()
    strArgs = Session.Property("CustomActionData")
    args = Split(strArgs, "/+/")

    home_dir= Replace(args(0), Chr(34), "")

    If GetVersion() >= 6 Then
        Set WshShell = CreateObject("WScript.Shell")

        ' Remove last backslash from home_dir
        install_dir = Left(home_dir, Len(home_dir) - 1)

        resetPerms = "icacls """ & install_dir & """ /reset /t"
        WshShell.run resetPerms, 0, True

        setPermsInherit = "icacls """ & install_dir & """ /inheritancelevel:r /q"
        WshShell.run setPermsInherit, 0, True

        grantAdminPerm = "icacls """ & install_dir & """ /grant *S-1-5-32-544:(OI)(CI)F"
        WshShell.run grantAdminPerm, 0, True

        grantSystemPerm = "icacls """ & install_dir & """ /grant *S-1-5-18:(OI)(CI)F"
        WshShell.run grantSystemPerm, 0, True

        grantAuthenticatedUsersPermSubfolders = "icacls """ & install_dir & """\* /grant *S-1-5-11:(OI)(CI)RX"
        WshShell.run grantAuthenticatedUsersPermSubfolders, 0, True

        grantAuthenticatedUsersPermSubfiles = "icacls """ & install_dir & """\* /grant *S-1-5-11:RX"
        WshShell.run grantAuthenticatedUsersPermSubfiles, 0, True

        grantAuthenticatedUsersPermFolder = "icacls """ & install_dir & """ /grant *S-1-5-11:RX"
        WshShell.run grantAuthenticatedUsersPermFolder, 0, True

        ' Remove Authenticated Users group for ossec.conf, last-ossec.conf, client.keys and authd.pass
        remAuthenticatedUsersPermsConf = "icacls """ & home_dir & "*ossec.conf" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsConf, 0, True

        remAuthenticatedUsersPermsKeys = "icacls """ & home_dir & "client.keys" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsKeys, 0, True

        remAuthenticatedUsersPermsAuthd = "icacls """ & home_dir & "authd.pass" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsAuthd, 0, True

        ' Remove the Authenticated Users group from the tmp directory to avoid
        ' inherited permissions on client.keys and ossec.conf when using win32ui.
        remAuthenticatedUsersPermsTmpDir = "icacls """ & home_dir & "tmp" & """ /remove:g *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsTmpDir, 0, True

    End If
End Function

Public Function CreateDumpRegistryKey()
    On Error Resume Next
    Dim strKeyPath, oReg
    Dim objCtx, objLocator, objServices
    Const HKEY_LOCAL_MACHINE = &H80000002

    Set objCtx = CreateObject("WbemScripting.SWbemNamedValueSet")
    objCtx.Add "__ProviderArchitecture", 64
    objCtx.Add "__RequiredArchitecture", True

    Set objLocator = CreateObject("WbemScripting.SWbemLocator")
    Set objServices = objLocator.ConnectServer(".", "root\default", "", "", , , , objCtx)
    Set oReg = objServices.Get("StdRegProv")

    strKeyPath = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\wazuh-agent.exe"

    oReg.CreateKey HKEY_LOCAL_MACHINE, strKeyPath
    oReg.SetExpandedStringValue HKEY_LOCAL_MACHINE, strKeyPath, "DumpFolder",  "%LOCALAPPDATA%\WazuhCrashDumps"
    oReg.SetDWORDValue HKEY_LOCAL_MACHINE, strKeyPath, "DumpType", 2

    Set objCtx = Nothing
    Set objLocator = Nothing
    Set objServices = Nothing
    Set oReg = Nothing

    CreateDumpRegistryKey = 0
End Function
