
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

' Defaults substituted for the components WAZUH_MANAGER_ENDPOINT leaves out. The prefix
' mirrors the manager's own default global_prefix (#38491) and the port
' DEFAULT_HTTPS_REMOTE_PORT (src/config/include/client-config.h).
Const MEP_DEFAULT_PORT = "1517"
Const MEP_DEFAULT_ENDPOINT = "/wazuh-manager/"

Dim MEP_HOST, MEP_PORT, MEP_ENDPOINT

' IsNumeric() is no use here: it accepts "1e3", "&h10", a leading sign and surrounding
' whitespace, none of which is a port.
private function mep_is_all_digits(value)
    Dim i, c
    mep_is_all_digits = False
    If Len(value) = 0 Then Exit Function
    For i = 1 To Len(value)
        c = Mid(value, i, 1)
        If c < "0" Or c > "9" Then Exit Function
    Next
    mep_is_all_digits = True
end function

' No WScript object exists in the MSI scripting host, so the reason goes where the
' shell installers put theirs -- the agent's own log.
private sub mep_log(home_dir, objFSO, raw, reason)
    Dim objLog
    Set objLog = objFSO.OpenTextFile(home_dir & "ossec.log", 8, True)
    objLog.WriteLine Now & " Invalid WAZUH_MANAGER_ENDPOINT '" & raw & "': " & reason
    objLog.Close
end sub

' Validates WAZUH_MANAGER_ENDPOINT against the <endpoint> grammar (#38624). <endpoint>
' takes this same language, so an accepted value is written into the config verbatim
' and this only decides whether to write it at all. MEP_HOST / MEP_PORT / MEP_ENDPOINT
' are still set, for callers that want the split:
'
'   [https://] host [:port] [/[prefix]]
'
' Only the host is mandatory. The subtlety worth keeping in mind: "no '/' at all" means
' "default prefix", while "a trailing '/' with nothing after it" is the operator's
' deliberate opt-out (#38614) and has to come out as an empty <endpoint></endpoint>.
'
' Same logic as parse_manager_endpoint() in src/init/register_configure_agent.sh and
' ParseManagerEndpoint() in src/init/inst-functions.sh -- a change in one belongs in all
' three. Returns True on success; on failure nothing is written and the reason is logged.
private function ParseManagerEndpoint(raw, home_dir, objFSO)

    Dim rest, scheme, authority, path, path_given, port_given, after_bracket, p, i, colons
    Dim port_digits

    ParseManagerEndpoint = False
    MEP_HOST = ""
    MEP_PORT = MEP_DEFAULT_PORT
    MEP_ENDPOINT = MEP_DEFAULT_ENDPOINT

    If raw = "" Then
        mep_log home_dir, objFSO, raw, "a manager address is required."
        Exit Function
    End If

    rest = raw

    ' Optional scheme. Only treated as one when no '/' precedes the "://", so a path
    ' that happens to contain "://" cannot be mistaken for a scheme.
    p = InStr(rest, "://")
    If p > 0 Then
        scheme = Left(rest, p - 1)
        If InStr(scheme, "/") = 0 Then
            rest = Mid(rest, p + 3)
            If LCase(scheme) <> "https" Then
                mep_log home_dir, objFSO, raw, "unsupported scheme '" & scheme & "://'; only https is served."
                Exit Function
            End If
        End If
    End If

    ' Authority up to the first '/', the prefix after it. Whether that '/' was there at
    ' all is what separates "default prefix" from "opt-out".
    p = InStr(rest, "/")
    If p > 0 Then
        authority = Left(rest, p - 1)
        path = Mid(rest, p + 1)
        path_given = True
    Else
        authority = rest
        path = ""
        path_given = False
    End If

    ' Host and optional port. A bracketed IPv6 literal ends at ']'; the brackets exist
    ' only to keep its colons apart from the port's and are dropped here, because
    ' <address> wants the bare literal (OS_IsValidIP does not match a bracketed one, and
    ' ModuleConfig::baseUrl re-brackets it for the URL itself).
    port_given = ""
    If Left(authority, 1) = "[" Then
        p = InStr(authority, "]")
        If p = 0 Then
            mep_log home_dir, objFSO, raw, "unterminated '[' in the address; a bracketed IPv6 literal needs a closing ']'."
            Exit Function
        End If
        MEP_HOST = Mid(authority, 2, p - 2)
        after_bracket = Mid(authority, p + 1)
        If after_bracket <> "" Then
            If Left(after_bracket, 1) = ":" Then
                port_given = Mid(after_bracket, 2)
            Else
                mep_log home_dir, objFSO, raw, "unexpected '" & after_bracket & "' after the bracketed address."
                Exit Function
            End If
        End If
        ' A zone id (%25<iface>) stays part of the host: the agent resolves it with
        ' if_nametoindex() at startup (#38624).
    Else
        colons = 0
        For i = 1 To Len(authority)
            If Mid(authority, i, 1) = ":" Then colons = colons + 1
        Next
        If colons > 1 Then
            mep_log home_dir, objFSO, raw, "an IPv6 address must be bracketed, e.g. [2001:db8::1]:" & MEP_DEFAULT_PORT & "."
            Exit Function
        ElseIf colons = 1 Then
            p = InStr(authority, ":")
            MEP_HOST = Left(authority, p - 1)
            port_given = Mid(authority, p + 1)
        Else
            MEP_HOST = authority
        End If
    End If

    If MEP_HOST = "" Then
        mep_log home_dir, objFSO, raw, "a manager address is required."
        Exit Function
    End If

    If port_given <> "" Then
        If Not mep_is_all_digits(port_given) Then
            mep_log home_dir, objFSO, raw, "port '" & port_given & "' is not a number."
            Exit Function
        End If
        ' CLng() holds a 32-bit Long, so it overflows above 2147483647. That error is not
        ' catchable here -- "On Error Resume Next" is procedure-scoped and this function
        ' declares none, so an overflow abandons the caller mid-statement: config() stops
        ' at the call, no diagnostic is written, and nothing it would have configured after
        ' that point happens. Narrow the value to something CLng can hold before using it.
        ' Leading zeros are stripped rather than rejected, so "000080" stays the port 80 --
        ' matching parse_manager_endpoint() in the shell installers.
        port_digits = port_given

        Do While Len(port_digits) > 1 And Left(port_digits, 1) = "0"
            port_digits = Mid(port_digits, 2)
        Loop

        ' Kept separate from the range test below because VBScript's Or does not
        ' short-circuit: both sides are evaluated, so CLng must never be reached with an
        ' oversized value.
        If Len(port_digits) > 5 Then
            mep_log home_dir, objFSO, raw, "port '" & port_given & "' is outside 1-65535."
            Exit Function
        End If

        If CLng(port_digits) < 1 Or CLng(port_digits) > 65535 Then
            mep_log home_dir, objFSO, raw, "port '" & port_given & "' is outside 1-65535."
            Exit Function
        End If
        MEP_PORT = port_given
    ElseIf Right(authority, 1) = ":" Then
        mep_log home_dir, objFSO, raw, "trailing ':' with no port."
        Exit Function
    End If

    If path_given Then
        Do While Left(path, 1) = "/"
            path = Mid(path, 2)
        Loop
        Do While Right(path, 1) = "/"
            path = Left(path, Len(path) - 1)
        Loop
        If path = "" Then
            MEP_ENDPOINT = ""
        Else
            MEP_ENDPOINT = "/" & path & "/"
        End If
    End If

    ParseManagerEndpoint = True

end function

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

    home_dir = Replace(args(0), Chr(34), "")
    OS_VERSION = Replace(args(1), Chr(34), "")
    WAZUH_MANAGER = Replace(args(2), Chr(34), "")
    WAZUH_MANAGER_PORT = Replace(args(3), Chr(34), "")
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
    WAZUH_MANAGER_ENDPOINT = Replace(args(16), Chr(34), "")

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

        If WAZUH_MANAGER <> "" or WAZUH_MANAGER_PORT <> "" or WAZUH_MANAGER_ENDPOINT <> "" or WAZUH_KEEP_ALIVE_INTERVAL <> "" or WAZUH_TIME_RECONNECT <> "" Then

            ' WAZUH_MANAGER_ENDPOINT carries the whole connection target (#38624) and
            ' takes priority when set. WAZUH_MANAGER (with WAZUH_MANAGER_PORT) still
            ' works: an <endpoint> is composed from them, so existing 4.x-era MSI command
            ' lines keep configuring an agent correctly.
            '
            ' The MSI's inability to carry a PROPERTY="" through the property table, which
            ' the old "/" sentinel worked around, stops mattering: the opt-out is spelled
            ' host/ and is non-empty, so it survives the property table on its own.
            final_endpoint = ""

            If WAZUH_MANAGER_ENDPOINT <> "" Then
                If ParseManagerEndpoint(WAZUH_MANAGER_ENDPOINT, home_dir, objFSO) Then
                    final_endpoint = WAZUH_MANAGER_ENDPOINT
                End If
                ' A rejected value leaves final_endpoint empty, so no block is written and
                ' the shipped placeholder stays -- the agent then fails loudly at startup
                ' rather than silently connecting somewhere unintended. Matches the shell
                ' installers.
            ElseIf WAZUH_MANAGER <> "" Then
                ' Only one manager block is supported, so a comma-separated list keeps its
                ' last entry (#37702 restrictions 2/3), matching the client parser.
                If InStr(WAZUH_MANAGER, ",") Then
                    ip_list = Split(WAZUH_MANAGER, ",")
                    final_endpoint = ip_list(UBound(ip_list))
                Else
                    final_endpoint = WAZUH_MANAGER
                End If

                ' A bare IPv6 literal needs bracketing once it shares a value with the
                ' port, or its trailing group reads as one.
                If InStr(final_endpoint, ":") > 0 And Left(final_endpoint, 1) <> "[" Then
                    final_endpoint = "[" & final_endpoint & "]"
                End If

                If WAZUH_MANAGER_PORT <> "" Then
                    final_endpoint = final_endpoint & ":" & WAZUH_MANAGER_PORT
                End If
            End If

            If final_endpoint <> "" Then
                Set re = new regexp
                re.Pattern = "\s+<(server|manager)>(.|\n)+?</\1>"

                ' A 5.x file is <agent><manager>; a 4.x file preserved across an upgrade
                ' is <client><server>, and the 5.x parser reads this block out of that one
                ' only under <server> -- writing <manager> there would strand the agent
                ' with no manager configured.
                If InStr(strText, "<agent>") > 0 Then
                    inner_tag = "manager"
                Else
                    inner_tag = "server"
                End If

                formatted_list = vbCrLf & _
                    "    <" & inner_tag & ">" & vbCrLf & _
                    "      <endpoint>" & final_endpoint & "</endpoint>" & vbCrLf & _
                    "    </" & inner_tag & ">"

                strText = re.Replace(strText, formatted_list)
            End If

            If WAZUH_KEEP_ALIVE_INTERVAL <> "" Then
                If InStr(strText, "<notify_time>") > 0 Then
                    Set re = new regexp
                    re.Pattern = "<notify_time>.*</notify_time>"
                    re.Global = True
                    strText = re.Replace(strText, "<notify_time>" & WAZUH_KEEP_ALIVE_INTERVAL & "</notify_time>")
                Else
                    ' The shipped configuration no longer carries the options it left at
                    ' their default, so there is nothing to replace on a fresh install.
                    ' Add the tag instead of dropping the property the user asked for.
                    strText = Replace(strText, "  </agent>", "    <notify_time>" & WAZUH_KEEP_ALIVE_INTERVAL & "</notify_time>" & vbCrLf & "  </agent>")
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

        If WAZUH_REGISTRATION_SERVER <> "" or WAZUH_REGISTRATION_PORT <> "" or WAZUH_REGISTRATION_PASSWORD <> "" or WAZUH_REGISTRATION_CA <> "" or WAZUH_REGISTRATION_CERTIFICATE <> "" or WAZUH_REGISTRATION_KEY <> "" or WAZUH_AGENT_NAME <> "" or WAZUH_AGENT_GROUP <> "" or ENROLLMENT_DELAY <> "" or WAZUH_MANAGER <> "" Then
            enrollment_list = "    <enrollment>" & vbCrLf
            enrollment_list = enrollment_list & "      <enabled>yes</enabled>" & vbCrLf
            enrollment_list = enrollment_list & "    </enrollment>" & vbCrLf
            enrollment_list = enrollment_list & "  </agent>" & vbCrLf

            strText = Replace(strText, "  </agent>", enrollment_list)

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
        ' The shipped template uses <manager>; <server> only survives on an
        ' ossec.conf written by previous 5.x agents, so this must anchor on
        ' either closing tag to keep inserting the profile block right after the
        ' address block on both fresh installs and upgrades.
        re.Pattern = "(</server>|</manager>)"
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
	Dim WshShell, majorVersion, currentVersion
	Set WshShell = CreateObject("WScript.Shell")

	On Error Resume Next

	' Windows 10/11 and Server 2016+ expose the major version as a DWORD.
	majorVersion = WshShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentMajorVersionNumber")
	If Err.Number = 0 And IsNumeric(majorVersion) Then
		GetVersion = CStr(majorVersion)
	Else
		' Older systems: parse the "CurrentVersion" string value (e.g. "6.1", "6.3").
		Err.Clear
		currentVersion = WshShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")
		If Err.Number = 0 And Len(currentVersion) > 0 Then
			GetVersion = Split(currentVersion, ".")(0)
		Else
			' Last resort: don't abort the install if the version can't be read, and don't
			' silently skip SetWazuhPermissions()'s ACL hardening either - every currently
			' supported Windows version satisfies ">= 6", so assume one instead of "0".
			GetVersion = "6"
		End If
	End If

	On Error GoTo 0
End Function

Public Function CheckSvcRunning()
    On Error Resume Next
    Set WshShell = CreateObject("WScript.Shell")
    scPath = WshShell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\sc.exe"

    Set objExec = WshShell.Exec(scPath & " query OssecSvc")
    If IsStateRunning(objExec.StdOut.ReadAll()) Then
        Session.Property("OSSECRUNNING") = "Running"
    End If

    Set objExec = WshShell.Exec(scPath & " query WazuhSvc")
    If IsStateRunning(objExec.StdOut.ReadAll()) Then
        Session.Property("WAZUHRUNNING") = "Running"
    End If

    CheckSvcRunning = 0
End Function

Private Function IsStateRunning(scOutput)
    IsStateRunning = False
    For Each line In Split(scOutput, vbCrLf)
        If InStr(line, "STATE") > 0 And InStr(line, ": 4 ") > 0 Then
            IsStateRunning = True
            Exit For
        End If
    Next
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

' Deletes legacy DBs when upgrading from pre-5.x; WiX filters the version.
Public Function CleanupLegacyDatabases()
    On Error Resume Next
    Dim strArgs, args, home_dir
    Dim fso

    ' Read CustomActionData: "[APPLICATIONFOLDER]"
    strArgs = Session.Property("CustomActionData")
    args = Split(strArgs, "/+/")
    home_dir = Replace(args(0), Chr(34), "")

    Set fso = CreateObject("Scripting.FileSystemObject")

    ' Remove legacy DB files
    fso.DeleteFile home_dir & "queue\syscollector\db\local.db", True
    fso.DeleteFile home_dir & "queue\fim\db\fim.db", True

    Set fso = Nothing

    CleanupLegacyDatabases = 0
End Function
