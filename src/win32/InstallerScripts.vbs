
' Script for configuration Windows agent.
' Copyright (C) 2015-2020, Wazuh Inc. <support@wazuh.com>
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

' Custom parameters
strArgs = Session.Property("CustomActionData")
args = Split(strArgs, ",")
home_dir        = Replace(args(0), Chr(34), "")
address         = Replace(args(1), Chr(34), "")
server_port     = Replace(args(2), Chr(34), "")
protocol        = Replace(args(3), Chr(34), "")
notify_time     = Replace(args(4), Chr(34), "")
time_reconnect  = Replace(args(5), Chr(34), "")

wazuh_address         = Replace(args(6), Chr(34), "")
wazuh_server_port     = Replace(args(7), Chr(34), "")
wazuh_protocol        = Replace(args(8), Chr(34), "")
wazuh_notify_time     = Replace(args(9), Chr(34), "")
wazuh_time_reconnect  = Replace(args(10), Chr(34), "")

If address = "" Then
    address = wazuh_address
End If

If server_port = "" Then
    server_port = wazuh_server_port
End If

If protocol = "" Then
    protocol = wazuh_protocol
End If

If notify_time = "" Then
    notify_time = wazuh_notify_time
End If

If time_reconnect = "" Then
    time_reconnect = wazuh_time_reconnect
End If

' Only try to set the configuration if variables are setted

Set objFSO = CreateObject("Scripting.FileSystemObject")

' Create an empty client.keys file on first install
If Not objFSO.fileExists(home_dir & "client.keys") Then
    objFSO.CreateTextFile(home_dir & "client.keys")
End If

If objFSO.fileExists(home_dir & "ossec.conf") Then
    ' Reading ossec.conf file
    Const ForReading = 1
    Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForReading)

    strText = objFile.ReadAll
    objFile.Close

    If address <> "" or server_port <> "" or protocol <> "" or notify_time <> "" or time_reconnect <> "" Then
        If address <> "" and InStr(address,";") > 0 Then 'list of address
            ip_list=Split(address,";")
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
        ElseIf address <> "" and InStr(strText,"<address>") > 0 Then
            strText = Replace(strText, "<address>0.0.0.0</address>", "<address>" & address & "</address>")

        ElseIf address <> "" Then 'single address
            ' Fix for the legacy server-ip and server-hostname keynames
            Set re = new regexp
            re.Pattern = "<server-ip>.*</server-ip>"
            re.Global = True
            strText = re.Replace(strText, "<server-ip>" & address & "</server-ip>")
            re.Pattern = "<server-hostname>.*</server-hostname>"
            re.Global = True
            strText = re.Replace(strText, "<server-hostname>" & address & "</server-hostname>")
            strText = Replace(strText, "<address>0.0.0.0</address>", "<address>" & address & "</address>")
        End If

        If server_port <> "" Then ' manager server_port
            If InStr(strText, "<port>") > 0 Then
                strText = Replace(strText, "<port>1514</port>", "<port>" & server_port & "</port>")
            Else
                ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "  <port>" & server_port & "</port>"& vbCrLf &"  </client>")
            End If

        End If

        If protocol <> "" Then
            If InStr(strText, "<protocol>") > 0 Then
                Set re = new regexp
                re.Pattern = "<protocol>.*</protocol>"
                re.Global = True
                strText = re.Replace(strText, "<protocol>" & LCase(protocol) & "</protocol>")
            Else
            ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "   <protocol>" & LCase(protocol) & "</protocol>"& vbCrLf &"  </client>")
            End If
        End If

        If notify_time <> "" Then
            If InStr(strText, "<notify_time>") > 0 Then
                Set re = new regexp
                re.Pattern = "<notify_time>.*</notify_time>"
                re.Global = True
                strText = re.Replace(strText, "<notify_time>" & notify_time & "</notify_time>")
            Else
                ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "   <notify_time>" & notify_time & "</notify_time>"& vbCrLf &"  </client>")
            End If
        End If

        If time_reconnect <> "" Then 'TODO fix the - and use _
            If InStr(strText, "<time-reconnect>") > 0 Then
                Set re = new regexp
                re.Pattern = "<time-reconnect>.*</time-reconnect>"
                re.Global = True
                strText = re.Replace(strText, "<time-reconnect>" & time_reconnect & "</time-reconnect>")
            Else
                ' Fix for the legacy files (not including the key)
                strText = Replace(strText, "</client>", "   <time-reconnect>" & time_reconnect & "</time-reconnect>"& vbCrLf &"  </client>")

            End If
        End If

        ' Writing the ossec.conf file
        const ForWriting = 2
        Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForWriting)
        objFile.WriteLine strText
        objFile.Close

    End If

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

If GetVersion() >= 6 Then
	Set WshShell = CreateObject("WScript.Shell")

	' Remove last backslash from home_dir
	install_dir = Left(home_dir, Len(home_dir) - 1)

	setPermsInherit = "icacls """ & install_dir & """ /inheritancelevel:d"
	WshShell.run setPermsInherit

	remUserPerm = "icacls """ & install_dir & """ /remove *S-1-5-32-545"
	WshShell.run remUserPerm

	' Remove Everyone group for ossec.conf
	remEveryonePerms = "icacls """ & home_dir & "ossec.conf" & """ /remove *S-1-1-0"
	WshShell.run remEveryonePerms
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
