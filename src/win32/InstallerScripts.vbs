
' Script for configuration Windows agent.
' Copyright (C) 2015-2019, Wazuh Inc. <support@wazuh.com>
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

If objFSO.fileExists(home_dir & "internal_options.conf") Then
    objFSO.DeleteFile(home_dir & "internal_options.conf")
End If

If objFSO.fileExists(home_dir & "ossec.conf") Then
    ' Reading ossec.conf file
    Const ForReading = 1
    Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForReading)

    strText = objFile.ReadAll
    objFile.Close

    ' Enable syscheck in a fresh installation
    strNewText = Replace(strText, "<teststring>", "<teststring>")
    If InStr(strText,"<address>0.0.0.0</address>") > 0 Then
        Set re = new regexp
        re.Pattern = "<disabled>yes</disabled>"
        re.Global = False
        strNewText = re.Replace(strNewText, "<disabled>no</disabled>")
        Set re = new regexp
        re.Pattern = "<!-- By default it is disabled. In the Install you must choose to enable it. -->"
        re.Global = True
        strNewText = re.Replace(strNewText, "")
    End If

    If address <> "" or server_port <> "" or protocol <> "" or notify_time <> "" or time_reconnect <> "" Then
        If address <> "" and InStr(address,";") > 0 Then 'list of address
            ip_list=Split(address,";")
            formatted_list ="    </server>" & vbCrLf
            not_replaced = True
            for each ip in ip_list
                If not_replaced Then
                  strNewText = Replace(strNewText, "<address>0.0.0.0</address>", "<address>" & ip & "</address>")
                  not_replaced = False
                Else
                    formatted_list = formatted_list & "    <server>" & vbCrLf
                    formatted_list = formatted_list & "      <address>" & ip & "</address>" & vbCrLf
                    formatted_list = formatted_list & "      <port>1514</port>" & vbCrLf
                    formatted_list = formatted_list & "      <protocol>udp</protocol>" & vbCrLf
                    formatted_list = formatted_list & "    </server>" & vbCrLf
                End If
            next
            strNewText = Replace(strNewText, "    </server>", formatted_list)
        ElseIf address <> "" and InStr(strText,"<address>") > 0 Then
            strNewText = Replace(strNewText, "<address>0.0.0.0</address>", "<address>" & address & "</address>")

        ElseIf address <> "" Then 'single address
            ' Fix for the legacy server-ip and server-hostname keynames
            Set re = new regexp
            re.Pattern = "<server-ip>.*</server-ip>"
            re.Global = True
            strNewText = re.Replace(strNewText, "<server-ip>" & address & "</server-ip>")
            re.Pattern = "<server-hostname>.*</server-hostname>"
            re.Global = True
            strNewText = re.Replace(strNewText, "<server-hostname>" & address & "</server-hostname>")
            strNewText = Replace(strNewText, "<address>0.0.0.0</address>", "<address>" & address & "</address>")
        End If

        If server_port <> "" Then ' manager server_port
            If InStr(strNewText, "<port>") > 0 Then
                strNewText = Replace(strNewText, "<port>1514</port>", "<port>" & server_port & "</port>")
            Else
                ' Fix for the legacy files (not including the key)
                strNewText = Replace(strNewText, "</client>", "  <port>" & server_port & "</port>"& vbCrLf &"  </client>")
            End If

        End If

        If protocol <> "" Then
            If InStr(strNewText, "<protocol>") > 0 Then
                Set re = new regexp
                re.Pattern = "<protocol>.*</protocol>"
                re.Global = True
                strNewText = re.Replace(strNewText, "<protocol>" & LCase(protocol) & "</protocol>")
            Else
            ' Fix for the legacy files (not including the key)
                strNewText = Replace(strNewText, "</client>", "   <protocol>" & LCase(protocol) & "</protocol>"& vbCrLf &"  </client>")
            End If
        End If

        If notify_time <> "" Then
            If InStr(strNewText, "<notify_time>") > 0 Then
                Set re = new regexp
                re.Pattern = "<notify_time>.*</notify_time>"
                re.Global = True
                strNewText = re.Replace(strNewText, "<notify_time>" & notify_time & "</notify_time>")
            Else
                ' Fix for the legacy files (not including the key)
                strNewText = Replace(strNewText, "</client>", "   <notify_time>" & notify_time & "</notify_time>"& vbCrLf &"  </client>")
            End If
        End If

        If time_reconnect <> "" Then 'TODO fix the - and use _
            If InStr(strNewText, "<time-reconnect>") > 0 Then
                Set re = new regexp
                re.Pattern = "<time-reconnect>.*</time-reconnect>"
                re.Global = True
                strNewText = re.Replace(strNewText, "<time-reconnect>" & time_reconnect & "</time-reconnect>")
            Else
                ' Fix for the legacy files (not including the key)
                strNewText = Replace(strNewText, "</client>", "   <time-reconnect>" & time_reconnect & "</time-reconnect>"& vbCrLf &"  </client>")

            End If
        End If


    End If

    ' Writing the ossec.conf file
    const ForWriting = 2
    Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForWriting)
    objFile.WriteLine strNewText
    objFile.Close

End If

config = 0

End Function
