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
    Const HKEY_LOCAL_MACHINE = &H80000002

    Set objRegistry = GetObject("winmgmts:\\.\root\default:StdRegProv")

    strComputer = "."
    Set objCtx = CreateObject("WbemScripting.SWbemNamedValueSet")
    objCtx.Add "__ProviderArchitecture", 64
    Set objLocator = CreateObject("Wbemscripting.SWbemLocator")
    Set objServices = objLocator.ConnectServer(strComputer,"root\default","","",,,,objCtx)
    Set objStdRegProv = objServices.Get("StdRegProv") 

    Const windowsDumpFolder = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\"
    Const defaultDumpCount = 20
    Const defaultDumpType = 2
    Const defaultDumpFolder = "dumps"

    If (IsEmpty(Session)) Then
        wazuhDumpFolder = WScript.Arguments.Item(0) + "\" + defaultDumpFolder
        executablesArgs = WScript.Arguments.Item(1)
    Else
        args = Split(Session.Property("CustomActionData"), "|")
        wazuhDumpFolder = Replace(args(0), Chr(34), "") + defaultDumpFolder
        executablesArgs = Replace(args(1), Chr(34), "")
    End If
    wazuhExecutables = Split(executablesArgs,",")

    Set inEnumKey = objStdRegProv.Methods_("EnumKey").Inparameters
    inEnumKey.Hdefkey = HKEY_LOCAL_MACHINE
    inEnumKey.Ssubkeyname = windowsDumpFolder
    Set Outparams = objStdRegProv.ExecMethod_("EnumKey", inEnumKey,,objCtx)

    Set inCreateKey = objStdRegProv.Methods_("CreateKey").Inparameters
    Set inSetDWORDValue = objStdRegProv.Methods_("SetDWORDValue").Inparameters
    Set inSetExpandedStringValue = objStdRegProv.Methods_("SetExpandedStringValue").Inparameters


    If Outparams.ReturnValue <> 0 Then
        ' Folder does not exist. Create a default one
        inCreateKey.Hdefkey = HKEY_LOCAL_MACHINE
        inCreateKey.Ssubkeyname = windowsDumpFolder
        objStdRegProv.ExecMethod_ "CreateKey", inCreateKey,,objCtx

        inSetDWORDValue.Hdefkey = HKEY_LOCAL_MACHINE
        inSetDWORDValue.Ssubkeyname = windowsDumpFolder
        inSetDWORDValue.Svaluename = "DumpCount"
        inSetDWORDValue.uvalue = 0

        objStdRegProv.ExecMethod_ "SetDWORDValue", inSetDWORDValue,,objCtx
    End If

    For Each executableFile In wazuhExecutables
        exeReg = windowsDumpFolder + executableFile

        inCreateKey.Hdefkey = HKEY_LOCAL_MACHINE
        inCreateKey.Ssubkeyname = exeReg
        objStdRegProv.ExecMethod_ "CreateKey", inCreateKey,,objCtx

        inSetDWORDValue.Hdefkey = HKEY_LOCAL_MACHINE
        inSetDWORDValue.Ssubkeyname = exeReg
        inSetDWORDValue.Svaluename = "DumpCount"
        inSetDWORDValue.uvalue = defaultDumpCount

        objStdRegProv.ExecMethod_ "SetDWORDValue", inSetDWORDValue,,objCtx

        inSetDWORDValue.Hdefkey = HKEY_LOCAL_MACHINE
        inSetDWORDValue.Ssubkeyname = exeReg
        inSetDWORDValue.Svaluename = "DumpType"
        inSetDWORDValue.uvalue = defaultDumpType

        objStdRegProv.ExecMethod_ "SetDWORDValue", inSetDWORDValue,,objCtx

        inSetExpandedStringValue.Hdefkey = HKEY_LOCAL_MACHINE
        inSetExpandedStringValue.Ssubkeyname = exeReg
        inSetExpandedStringValue.Svaluename = "DumpFolder"
        inSetExpandedStringValue.svalue = wazuhDumpFolder

        objStdRegProv.ExecMethod_ "SetExpandedStringValue", inSetExpandedStringValue,,objCtx

    Next
    EnableDumps = 0
End Function


EnableDumps()
