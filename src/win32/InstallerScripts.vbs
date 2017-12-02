
' Script for configuration Windows agent.
' Copyright (c) 2017 Wazuh, Inc <support@wazuh.com>
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
home_dir        = Replace(args(0), Chr(34), "") 'APPLICATIONFOLDER
address         = Replace(args(1), Chr(34), "") 'ADDRESS
server_port     = Replace(args(2), Chr(34), "") 'SERVER_PORT
protocol        = Replace(args(3), Chr(34), "") 'PROTOCOL
notify_time     = Replace(args(4), Chr(34), "") 'NOTIFY_TIME
time_reconnect  = Replace(args(5), Chr(34), "") 'TIME_RECONNECT

' Only try to set the configuration if variables are setted
If address <> "" or server_port <> "" or protocol <> "" or notify_time <> "" or time_reconnect <> "" Then

    Set objFSO = CreateObject("Scripting.FileSystemObject")
    If objFSO.fileExists(home_dir & "ossec.conf") Then
        ' Reading ossec.conf file
        Const ForReading = 1
        Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForReading)

        strText = objFile.ReadAll
        objFile.Close

        ' Modifying values in ossec.conf
        strNewText = Replace(strText, "<teststring>", "<teststring>")

        If address <> "" and InStr(address,",") > 0 Then 'list of address
            list=Split(address,",")
            formatted_list =""
            for each ip in list
                formatted_list = formatted_list & "    <address>" & ip & "</address>" & vbCrLf
            next
            strNewText = Replace(strNewText, "      <address>0.0.0.0</address>", formatted_list)

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
                Set re = new regexp
                re.Pattern = "<port>.*</port>"
                re.Global = True
                strNewText = re.Replace(strNewText, "<port>" & server_port & "</port>")
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
                strNewText = re.Replace(strNewText, "<protocol>" & protocol & "</protocol>")
            Else
            ' Fix for the legacy files (not including the key)
                strNewText = Replace(strNewText, "</client>", "   <protocol>" & protocol & "</protocol>"& vbCrLf &"  </client>")
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

        ' Writing the ossec.conf file
        const ForWriting = 2
        Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForWriting)
        objFile.WriteLine strNewText
        objFile.Close

    End If

End If

config = 0

End Function
