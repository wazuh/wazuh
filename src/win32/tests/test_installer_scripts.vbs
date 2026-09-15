' Copyright (C) 2015, Wazuh Inc.
'
' This program is free software; you can redistribute it
' and/or modify it under the terms of the GNU General Public
' License (version 2) as published by the FSF - Free Software
' Foundation.
'
' Drives config() in ../InstallerScripts.vbs against a throwaway install directory, so the
' refusal rules of #39063 are asserted on Windows rather than read next to the Linux ones.
' Mirrors src/init/tests/test_enrollment_token.sh case for case; the two must agree, because
' "the same rules on every platform" is a claim a reader cannot check by eye.
'
' Run on the agent host, from this directory:
'
'   cscript //nologo test_installer_scripts.vbs
'
' Three seams, because config() is written to be called by Windows Installer and not by a test:
'   - Session.Property("CustomActionData") is replaced with the payload literal,
'   - SetWazuhPermissions() is stubbed out, since it shells out to icacls,
'   - wazuh-agent.exe is replaced with a .cmd stub, so the cases run without an agent build.

' Deliberately no Option Explicit: ExecuteGlobal shares this script's namespace, and
' InstallerScripts.vbs declares none of its variables, so requiring declaration here would
' refuse to load the very code under test.

Dim objFSO, checks, failures, targetSource
Set objFSO = CreateObject("Scripting.FileSystemObject")
checks = 0
failures = 0

targetSource = objFSO.GetParentFolderName(objFSO.GetParentFolderName(WScript.ScriptFullName)) & "\InstallerScripts.vbs"

' The shipped placeholder, as the packaged ossec.conf carries it. A refusal must leave this.
' Dim over Const: VBScript's Const takes a literal only, and this is a concatenation.
Dim PLACEHOLDER_CONF
PLACEHOLDER_CONF = "<ossec_config>" & vbCrLf & _
                         "  <agent>" & vbCrLf & _
                         "    <manager>" & vbCrLf & _
                         "      <endpoint>IP:1517/wazuh-manager/</endpoint>" & vbCrLf & _
                         "    </manager>" & vbCrLf & _
                         "  </agent>" & vbCrLf & _
                         "</ossec_config>"

' A 4.x file preserved across an in-place upgrade: <client><server><address>, with a <port>
' the 5.x agent no longer reads. The wrapper must stay <server> -- the 5.x parser reads this
' block out of <client> only under that name -- and the stale <port> must not survive.
Dim LEGACY_CONF
LEGACY_CONF = "<ossec_config>" & vbCrLf & _
              "  <client>" & vbCrLf & _
              "    <server>" & vbCrLf & _
              "      <address>MANAGER_IP</address>" & vbCrLf & _
              "      <port>1514</port>" & vbCrLf & _
              "    </server>" & vbCrLf & _
              "  </client>" & vbCrLf & _
              "</ossec_config>"

' Opaque to the installer -- only the stub decoder reads it -- so a recognisable literal.
Const TOKEN = "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCJ9"

Sub Check(name, expected, actual)
    checks = checks + 1
    If CStr(expected) = CStr(actual) Then
        WScript.Echo "ok   - " & name
    Else
        failures = failures + 1
        WScript.Echo "FAIL - " & name
        WScript.Echo "--- expected ---"
        WScript.Echo CStr(expected)
        WScript.Echo "--- actual ---"
        WScript.Echo CStr(actual)
        WScript.Echo "---"
    End If
End Sub

Function ReadAllText(path)
    Dim f
    ReadAllText = ""
    If Not objFSO.FileExists(path) Then Exit Function
    Set f = objFSO.OpenTextFile(path, 1)
    If Not f.AtEndOfStream Then ReadAllText = f.ReadAll
    f.Close
End Function

' A throwaway install directory with a stub decoder that prints `description` and exits `status`.
Function MakeHomeDir(description, status)
    MakeHomeDir = MakeHomeDirWith(description, status, PLACEHOLDER_CONF)
End Function

Function MakeHomeDirWith(description, status, confBody)
    Dim dir, f, line, parts, i
    dir = objFSO.GetSpecialFolder(2) & "\" & objFSO.GetTempName() & "\"
    objFSO.CreateFolder dir
    Set f = objFSO.CreateTextFile(dir & "ossec.conf", True)
    f.Write confBody
    f.Close

    Set f = objFSO.CreateTextFile(dir & "wazuh-agent.cmd", True)
    f.WriteLine "@echo off"
    f.WriteLine "more > nul"
    parts = Split(description, vbLf)
    For i = 0 To UBound(parts)
        line = Trim(parts(i))
        If line <> "" Then f.WriteLine "echo " & line
    Next
    f.WriteLine "exit /b " & status
    f.Close

    MakeHomeDirWith = dir
End Function

Sub RemoveDir(dir)
    On Error Resume Next
    objFSO.DeleteFolder Left(dir, Len(dir) - 1), True
    On Error Goto 0
End Sub

' Load config() with the three seams patched, and run it against `dir` with `payload`.
Sub RunConfig(dir, payload)
    Dim code
    code = ReadAllText(targetSource)
    code = Replace(code, "Session.Property(""CustomActionData"")", """" & payload & """")
    ' Rename the real one out of the way and give its name to a no-op, rather than blanking the
    ' call: "SetWazuhPermissions()" is also how its own definition line reads, so a blanket
    ' replace turns "Public Function SetWazuhPermissions()" into a comment and the whole file
    ' stops compiling.
    code = Replace(code, "Public Function SetWazuhPermissions()", "Public Function SetWazuhPermissionsReal()")
    code = code & vbCrLf & "Public Function SetWazuhPermissions()" & vbCrLf & "End Function" & vbCrLf
    code = Replace(code, """wazuh-agent.exe""", """wazuh-agent.cmd""")
    ExecuteGlobal code
    config()
End Sub

' The payload config() splits on "/+/", in the order wazuh-installer.wxs packs it. Only the
' fields a case varies are named; the rest stay empty.
Function Payload(home_dir, token, agentName, sslVerification, removedName, removedValue)
    Dim fields, i, names
    names = Array("APPLICATIONFOLDER", "OS_VERSION", "WAZUH_ENROLLMENT_TOKEN", _
                  "WAZUH_AGENT_NAME", "WAZUH_AGENT_GROUP", "WAZUH_KEEP_ALIVE_INTERVAL", _
                  "WAZUH_TIME_RECONNECT", "ENROLLMENT_DELAY", "WAZUH_SSL_VERIFICATION", _
                  "WAZUH_MANAGER", "WAZUH_MANAGER_PORT", "WAZUH_MANAGER_ENDPOINT", _
                  "WAZUH_REGISTRATION_SERVER", "WAZUH_REGISTRATION_PORT", _
                  "WAZUH_REGISTRATION_PASSWORD", "WAZUH_REGISTRATION_CA", _
                  "WAZUH_REGISTRATION_CERTIFICATE", "WAZUH_REGISTRATION_KEY", _
                  "SSL_VERIFICATION", "ADDRESS", "SERVER_PORT", "AUTHD_SERVER", _
                  "AUTHD_PORT", "PASSWORD", "CERTIFICATE", "PEM", "KEY")
    ReDim fields(UBound(names))
    For i = 0 To UBound(names)
        fields(i) = ""
    Next
    fields(0) = home_dir
    fields(1) = "10"
    fields(2) = token
    fields(3) = agentName
    fields(8) = sslVerification
    If removedName <> "" Then
        For i = 0 To UBound(names)
            If names(i) = removedName Then fields(i) = removedValue
        Next
    End If
    Payload = Join(fields, "/+/")
End Function

Function EndpointOf(dir)
    Dim text, re, m
    text = ReadAllText(dir & "ossec.conf")
    Set re = new regexp
    re.Pattern = "<endpoint>(.*)</endpoint>"
    Set m = re.Execute(text)
    If m.Count > 0 Then EndpointOf = m(0).SubMatches(0) Else EndpointOf = ""
End Function

Function LogHas(dir, needle)
    LogHas = (InStr(ReadAllText(dir & "ossec.log"), needle) > 0)
End Function

' Anchored on the space before the name, so a check for KEY cannot be satisfied by a line about
' WAZUH_REGISTRATION_KEY. Eight of the eighteen removed names are a substring of another, which
' is exactly the misalignment two parallel 18-element arrays invite.
Function LogHasVariable(dir, name)
    LogHasVariable = (InStr(ReadAllText(dir & "ossec.log"), " " & name & " is not supported in 5.0") > 0)
End Function

Function Exists(dir, name)
    If objFSO.FileExists(dir & name) Then Exists = "present" Else Exists = "absent"
End Function

' ---------------------------------------------------------------- A token on its own

Dim dir

dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0)
RunConfig dir, Payload(dir, TOKEN, "", "", "", "")
Check "a token alone writes its address into <endpoint>", "siem.example.local", EndpointOf(dir)
Check "a token alone stores the token verbatim", TOKEN, Trim(ReadAllText(dir & "enrollment_token"))
Check "a token alone writes no authd.pass", "absent", Exists(dir, "authd.pass")
RemoveDir dir

dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: absent", 0)
RunConfig dir, Payload(dir, TOKEN, "", "", "", "")
Check "a credential-less token is not an error", "siem.example.local", EndpointOf(dir)
RemoveDir dir

' ---------------------------------------------------------------- the decoder's own failures

dir = MakeHomeDir("", 2)
RunConfig dir, Payload(dir, TOKEN, "", "", "", "")
Check "a token the decoder refuses: names ERR_BAD_TOKEN", True, LogHas(dir, "ERR_BAD_TOKEN")
Check "a token the decoder refuses: leaves the placeholder", "IP:1517/wazuh-manager/", EndpointOf(dir)
Check "a token the decoder refuses: stores no token", "absent", Exists(dir, "enrollment_token")
RemoveDir dir

dir = MakeHomeDir("ver: 1" & vbLf & "credential: absent", 0)
RunConfig dir, Payload(dir, TOKEN, "", "", "", "")
Check "a token carrying no address: names ERR_BAD_TOKEN", True, LogHas(dir, "ERR_BAD_TOKEN")
Check "a token carrying no address: stores no token", "absent", Exists(dir, "enrollment_token")
RemoveDir dir

' ---------------------------------------------------------------- mode alongside a token

Dim modes, mi
modes = Array("full", "certificate", "system", "none")
For mi = 0 To UBound(modes)
    dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0)
    RunConfig dir, Payload(dir, TOKEN, "", modes(mi), "", "")
    Check "a token with WAZUH_SSL_VERIFICATION=" & modes(mi) & ": still writes the token's address", _
          "siem.example.local", EndpointOf(dir)
    Check "a token with WAZUH_SSL_VERIFICATION=" & modes(mi) & ": writes that mode", True, _
          (InStr(ReadAllText(dir & "ossec.conf"), "<verification_mode>" & modes(mi) & "</verification_mode>") > 0)
    Check "a token with WAZUH_SSL_VERIFICATION=" & modes(mi) & ": still stores the token", _
          "present", Exists(dir, "enrollment_token")
    RemoveDir dir
Next

' ---------------------------------------------------------------- no token at all

dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0)
RunConfig dir, Payload(dir, "", "", "", "", "")
Check "no token and no endpoint names the missing manager", True, LogHas(dir, "INFO_NO_MANAGER")
Check "no token leaves the shipped placeholder", "IP:1517/wazuh-manager/", EndpointOf(dir)
Check "no token stores no token", "absent", Exists(dir, "enrollment_token")
RemoveDir dir

dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0)
RunConfig dir, Payload(dir, "", "hand-configured", "system", "", "")
Check "no token still writes <agent_name>", True, _
      (InStr(ReadAllText(dir & "ossec.conf"), "<agent_name>hand-configured</agent_name>") > 0)
Check "no token still writes <verification_mode>", True, _
      (InStr(ReadAllText(dir & "ossec.conf"), "<verification_mode>system</verification_mode>") > 0)
RemoveDir dir

' ---------------------------------------------------------------- a 4.x file kept on upgrade

dir = MakeHomeDirWith("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0, LEGACY_CONF)
RunConfig dir, Payload(dir, TOKEN, "", "", "", "")
Check "a 4.x file gets the token's address", "siem.example.local", EndpointOf(dir)
Check "a 4.x file keeps <server> as the wrapper, not <manager>", True, _
      (InStr(ReadAllText(dir & "ossec.conf"), "<server>") > 0)
Check "a 4.x file is not given a <manager> the parser will not read there", False, _
      (InStr(ReadAllText(dir & "ossec.conf"), "<manager>") > 0)
Check "the stale <port> does not survive the rewrite", False, _
      (InStr(ReadAllText(dir & "ossec.conf"), "<port>1514</port>") > 0)
RemoveDir dir

' ---------------------------------------------------------------- removed names are reported

Dim removed, ri
removed = Array("WAZUH_MANAGER", "WAZUH_MANAGER_PORT", "WAZUH_MANAGER_ENDPOINT", _
                "WAZUH_REGISTRATION_SERVER", "WAZUH_REGISTRATION_PORT", _
                "WAZUH_REGISTRATION_PASSWORD", "WAZUH_REGISTRATION_CA", _
                "WAZUH_REGISTRATION_CERTIFICATE", "WAZUH_REGISTRATION_KEY", _
                "SSL_VERIFICATION", "ADDRESS", "SERVER_PORT", "AUTHD_SERVER", _
                "AUTHD_PORT", "PASSWORD", "CERTIFICATE", "PEM", "KEY")
For ri = 0 To UBound(removed)
    dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0)
    RunConfig dir, Payload(dir, TOKEN, "", "", removed(ri), "some-value")
    Check removed(ri) & " is reported as removed", True, LogHasVariable(dir, removed(ri))
    RemoveDir dir
Next

dir = MakeHomeDir("ver: 1" & vbLf & "adr: siem.example.local" & vbLf & "credential: present", 0)
RunConfig dir, Payload(dir, TOKEN, "", "", "SSL_VERIFICATION", "system")
Check "SSL_VERIFICATION is reported as renamed, not merely removed", True, _
      (InStr(ReadAllText(dir & "ossec.log"), "renamed to WAZUH_SSL_VERIFICATION; the old name is not read.") > 0)
Check "SSL_VERIFICATION under its old name reaches no <verification_mode>", False, _
      (InStr(ReadAllText(dir & "ossec.conf"), "<verification_mode>") > 0)
RemoveDir dir

WScript.Echo ""
WScript.Echo checks & " checks, " & failures & " failed"
If failures > 0 Then WScript.Quit 1
WScript.Quit 0
