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
' ------------------------------------------------

Public Function EnableDumps()
    Set WshShell = CreateObject("WScript.Shell")

    Const windowsDumpFolder = "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\"
    Const defaultDumpCount = 20
    Const defaultDumpType = 2
    Const defaultDumpFolder = "dumps"

    If (IsEmpty(Session)) Then
        wazuhDumpFolder = WScript.Arguments.Item(0) + "\" + defaultDumpFolder
        executablesArgs = WScript.Arguments.Item(1)
    Else
        args = Split(Session.Property("CustomActionData"), "|")
        wazuhDumpFolder = Replace(args(0), Chr(34), "") + "\" + defaultDumpFolder
        executablesArgs = Replace(args(1), Chr(34), "")
    End If
    wazuhExecutables = Split(executablesArgs,",")
	On Error Resume Next
    WshShell.RegRead windowsDumpFolder
    If Err.Number <> 0 Then
        ' Folder does not exist. Create a default one
        WshShell.RegWrite windowsDumpFolder + "DumpCount", 0, "REG_DWORD"
    End If

    For Each executableFile In wazuhExecutables
        exeReg = windowsDumpFolder + executableFile + "\"
        WshShell.RegWrite exeReg + "DumpFolder", wazuhDumpFolder, "REG_EXPAND_SZ"
        WshShell.RegWrite exeReg + "DumpCount", defaultDumpCount, "REG_DWORD"
        WshShell.RegWrite exeReg + "DumpType", defaultDumpType, "REG_DWORD"
    Next
    EnableDumps = 0
End Function

EnableDumps()
