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

Public Function DisableDumps()
	Const HKEY_LOCAL_MACHINE = &H80000002

	Set objRegistry = GetObject("winmgmts:\\.\root\default:StdRegProv")

	strComputer = "."
	Set objCtx = CreateObject("WbemScripting.SWbemNamedValueSet")
	objCtx.Add "__ProviderArchitecture", 64
	Set objLocator = CreateObject("Wbemscripting.SWbemLocator")
	Set objServices = objLocator.ConnectServer(strComputer,"root\default","","",,,,objCtx)
	Set objStdRegProv = objServices.Get("StdRegProv")

    Const windowsDumpFolder = "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\"

    If (IsEmpty(Session)) Then
        executablesArgs = WScript.Arguments.Item(0)
    Else
        executablesArgs = Replace(Session.Property("CustomActionData"), Chr(34), "")
    End If
    wazuhExecutables = Split(executablesArgs,",")

	Set inDeleteKey = objStdRegProv.Methods_("DeleteKey").Inparameters
	inDeleteKey.Hdefkey = HKEY_LOCAL_MACHINE

    For Each executableFile In wazuhExecutables
        exeReg = windowsDumpFolder + executableFile

		inDeleteKey.Ssubkeyname = exeReg
		objStdRegProv.ExecMethod_ "DeleteKey", inDeleteKey,,objCtx

    Next
    DisableDumps = 0
End Function


DisableDumps()
