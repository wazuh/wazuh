
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


' Generic installer message, written to the same ossec.log the agent uses.
private sub install_log(home_dir, objFSO, message)
    Dim objLog
    Set objLog = objFSO.OpenTextFile(home_dir & "ossec.log", 8, True)
    objLog.WriteLine Now & " " & message
    objLog.Close
end sub

' Escapes the three characters that are structurally significant in XML content --
' '&', '<', '>' -- so a value written verbatim into ossec.conf (a CA path, in
' particular) can never be mistaken for markup or break the file's well-formedness.
' '&' first: escaping '<'/'>' introduces new literal '&' characters (as part of
' "&lt;"/"&gt;") that must not themselves be re-escaped by a later Replace() call.
Function XmlEscape(text)
    XmlEscape = Replace(Replace(Replace(text, "&", "&amp;"), "<", "&lt;"), ">", "&gt;")
End Function

' Strips XML comments from a working copy so the WAZUH_REGISTRATION_CA checks below
' don't match tag content that's still inside a "<!-- ... -->" wrapper -- mirrors
' strip_xml_comments() in pkg_installer.sh and its port in do_upgrade.ps1. "[\s\S]*?"
' spans a multi-line comment (VBScript's regexp "." does not match newline); non-greedy
' so two separate comments don't merge into one.
' Replace a paired <tag>...</tag> value in place. Two call sites carried an identical inline
' regexp; one helper is one place for them to stay identical.
Function RegExpReplaceTag(text, tagName, value)
    Dim re
    Set re = new regexp
    re.Pattern = "<" & tagName & ">.*</" & tagName & ">"
    re.Global = True
    RegExpReplaceTag = re.Replace(text, "<" & tagName & ">" & value & "</" & tagName & ">")
End Function

' Decode an enrollment token with the agent's own codec instead of reimplementing base64url and
' JSON here: a token this accepts is exactly a token w_agent_token_bootstrap() will accept at the
' first start. The token goes in on stdin, never as an argument -- a command line is visible to
' every user on the machine through Task Manager. The output never contains the credential.
'
' Sets adr to the token's address. Returns the decoder's own exit code: 0 accepted, 2 refused,
' anything else means it could not be run at all, which is a different problem for an operator.
Function DecodeEnrollmentToken(home_dir, objFSO, token, ByRef adr)

    Dim shell, exec, output, parts, i, line

    adr = ""

    ' Initialised to "never ran", not left Empty: this file runs under On Error Resume Next, and
    ' an Exec that throws would otherwise return Empty, which VBScript compares equal to 0 -- so
    ' both the "refused" and the "did not run" tests would be False and a decoder that never
    ' started would be reported as a bad token, which is the one confusion the two codes exist
    ' to prevent.
    DecodeEnrollmentToken = 127

    If Not objFSO.FileExists(home_dir & "wazuh-agent.exe") Then
        DecodeEnrollmentToken = 127
        Exit Function
    End If

    Set shell = CreateObject("WScript.Shell")
    Set exec = shell.Exec(Chr(34) & home_dir & "wazuh-agent.exe" & Chr(34) & " --show-token")

    exec.StdIn.Write token
    exec.StdIn.Close

    ' ReadAll blocks until the child closes the stream, which it does when it exits, so the exit
    ' code below is already settled by the time it returns. Same shape as CheckSvcRunning()'s
    ' use of Exec further down.
    output = exec.StdOut.ReadAll

    ' ReadAll returns when the stream closes, which is not necessarily when the process has
    ' exited; ExitCode read too early reports 0 for a decoder that failed, which would surface
    ' as a bad token rather than as a decoder that never ran.
    Do While exec.Status = 0
    Loop

    DecodeEnrollmentToken = exec.ExitCode

    parts = Split(output, vbLf)
    For i = 0 To UBound(parts)
        line = Replace(parts(i), vbCr, "")
        If Left(line, 5) = "adr: " Then
            adr = Mid(line, 6)
        End If
    Next

End Function

Function StrippedOfComments(text)
    Dim reComment
    Set reComment = New RegExp
    reComment.Pattern = "<!--[\s\S]*?-->"
    reComment.Global = True
    StrippedOfComments = reComment.Replace(text, "")
End Function
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

    ' Registration. The enrollment token is the only input.
    WAZUH_ENROLLMENT_TOKEN = Replace(args(2), Chr(34), "")

    ' Never registration, so untouched by that rule.
    WAZUH_AGENT_NAME = Replace(args(3), Chr(34), "")
    WAZUH_AGENT_GROUP = Replace(args(4), Chr(34), "")
    WAZUH_KEEP_ALIVE_INTERVAL = Replace(args(5), Chr(34), "")
    WAZUH_TIME_RECONNECT = Replace(args(6), Chr(34), "")
    ENROLLMENT_DELAY = Replace(args(7), Chr(34), "")
    WAZUH_SSL_VERIFICATION = Replace(args(8), Chr(34), "")

    ' Removed. Read only so a command line that still sets one is told it no longer does
    ' anything. The order is not free: these are positional reads of the CustomActionData
    ' payload built in wazuh-installer.wxs, so a name added or dropped here has to move with
    ' its field there or every later index shifts onto the wrong property.
    removed_names = Array("WAZUH_MANAGER", "WAZUH_MANAGER_PORT", "WAZUH_MANAGER_ENDPOINT", _
                          "WAZUH_REGISTRATION_SERVER", "WAZUH_REGISTRATION_PORT", _
                          "WAZUH_REGISTRATION_PASSWORD", "WAZUH_REGISTRATION_CA", _
                          "WAZUH_REGISTRATION_CERTIFICATE", "WAZUH_REGISTRATION_KEY", _
                          "ADDRESS", "SERVER_PORT", "AUTHD_SERVER", _
                          "AUTHD_PORT", "PASSWORD", "CERTIFICATE", "PEM", "KEY")
    removed_values = Array(Replace(args(9), Chr(34), ""), Replace(args(10), Chr(34), ""), _
                           Replace(args(11), Chr(34), ""), Replace(args(12), Chr(34), ""), _
                           Replace(args(13), Chr(34), ""), Replace(args(14), Chr(34), ""), _
                           Replace(args(15), Chr(34), ""), Replace(args(16), Chr(34), ""), _
                           Replace(args(17), Chr(34), ""), Replace(args(19), Chr(34), ""), _
                           Replace(args(20), Chr(34), ""), Replace(args(21), Chr(34), ""), _
                           Replace(args(22), Chr(34), ""), Replace(args(23), Chr(34), ""), _
                           Replace(args(24), Chr(34), ""), Replace(args(25), Chr(34), ""), _
                           Replace(args(26), Chr(34), ""))

    ' Renamed, not removed, and with no alias -- so an install still passing the old spelling
    ' would silently get no verification mode at all and fall through the resolution ladder.
    SSL_VERIFICATION_OLD = Replace(args(18), Chr(34), "")

    ' Only try to set the configuration if variables are setted

    Set objFSO = CreateObject("Scripting.FileSystemObject")

    ' Create an empty client.keys file on first install
    If Not objFSO.fileExists(home_dir & "client.keys") Then
        objFSO.CreateTextFile(home_dir & "client.keys")
    End If

    ' Report every removed name that was still passed, warn-and-ignore rather than silence.
    For removed_i = 0 To UBound(removed_names)
        If removed_values(removed_i) <> "" Then
            install_log home_dir, objFSO, removed_names(removed_i) & " is not supported in 5.0 and was ignored: registration is configured by WAZUH_ENROLLMENT_TOKEN alone."
        End If
    Next

    If SSL_VERIFICATION_OLD <> "" Then
        install_log home_dir, objFSO, "SSL_VERIFICATION is not supported in 5.0 and was ignored: renamed to WAZUH_SSL_VERIFICATION; the old name is not read."
    End If

    ' Settle the properties against each other before anything is written. A refusal leaves the
    ' configuration the package shipped rather than a half-applied one.
    token_adr = ""
    token_ok = False

    ' A token that was supplied and cannot be honoured stops the whole configuration, exactly as
    ' main() in register_configure_agent.sh returns before its first writer: an unverified
    ' enrollment is not a possible outcome once a token was passed. An *absent* token is not a
    ' refusal in that sense -- registration does not happen and says so, but the settings that
    ' were never about registration still apply, which is what a hand-configured install needs.
    deployment_refused = False

    If WAZUH_ENROLLMENT_TOKEN = "" Then
        install_log home_dir, objFSO, "No manager configured [INFO_NO_MANAGER]: WAZUH_ENROLLMENT_TOKEN was not supplied, so the agent does not know where to connect. Set <manager><endpoint> in ossec.conf by hand, or reinstall with a token."
    Else
        ' Decoded before the endpoint is looked at, matching resolve_deployment_conflicts() in
        ' src/init/register_configure_agent.sh: a malformed token passed together with an
        ' endpoint is reported as a bad token on both platforms, not as a conflict on one.
        token_status = DecodeEnrollmentToken(home_dir, objFSO, WAZUH_ENROLLMENT_TOKEN, token_adr)
        If token_status = 2 Then
            install_log home_dir, objFSO, "Deployment variables refused [ERR_BAD_TOKEN]: WAZUH_ENROLLMENT_TOKEN was refused by the token decoder; no manager was configured from it and no token was stored."
            token_adr = ""
            WAZUH_ENROLLMENT_TOKEN = ""
            deployment_refused = True
        ElseIf token_status <> 0 Then
            install_log home_dir, objFSO, "Deployment variables refused [ERR_NO_DECODER]: could not run wazuh-agent.exe --show-token (exit " & token_status & "); the enrollment token was left unread and no token was stored."
            token_adr = ""
            WAZUH_ENROLLMENT_TOKEN = ""
            deployment_refused = True
        ElseIf token_adr = "" Then
            install_log home_dir, objFSO, "Deployment variables refused [ERR_BAD_TOKEN]: WAZUH_ENROLLMENT_TOKEN carries no address; no token was stored."
            WAZUH_ENROLLMENT_TOKEN = ""
            deployment_refused = True
        Else
            token_ok = True
        End If
    End If

    If (Not deployment_refused) And objFSO.fileExists(home_dir & "ossec.conf") Then
        ' Reading ossec.conf file
        Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForReading)

        strText = objFile.ReadAll
        objFile.Close

        ' The token's address is the only thing that reaches <endpoint>. Written verbatim:
        ' w_etoken_decode() validated it against this same grammar before --show-token would
        ' print it, so there is nothing left to check here.
        '
        ' The whole <manager>/<server> block is replaced, not just the inner tag: a block kept
        ' from a 4.x file would otherwise keep its stale <port> alongside the new <endpoint>, and
        ' nothing here should depend on what the shipped placeholder happens to say. A 5.x file is
        ' <agent><manager>; a 4.x file preserved across an upgrade is <client><server>, and the
        ' 5.x parser reads this block out of that one only under <server> -- writing <manager>
        ' there would strand the agent with no manager configured.
        If token_adr <> "" Then
            Set endpointRe = new regexp
            endpointRe.Pattern = "\s+<(server|manager)>(.|\n)+?</\1>"

            If InStr(strText, "<agent>") > 0 Then
                inner_tag = "manager"
            Else
                inner_tag = "server"
            End If

            formatted_list = vbCrLf & _
                "    <" & inner_tag & ">" & vbCrLf & _
                "      <endpoint>" & XmlEscape(token_adr) & "</endpoint>" & vbCrLf & _
                "    </" & inner_tag & ">"

            strText = endpointRe.Replace(strText, formatted_list)
        End If

        If WAZUH_KEEP_ALIVE_INTERVAL <> "" Then
            If InStr(strText, "<notify_time>") > 0 Then
                strText = RegExpReplaceTag(strText, "notify_time", WAZUH_KEEP_ALIVE_INTERVAL)
            Else
                strText = Replace(strText, "  </agent>", "    <notify_time>" & WAZUH_KEEP_ALIVE_INTERVAL & "</notify_time>" & vbCrLf & "  </agent>")
            End If
        End If

        If WAZUH_TIME_RECONNECT <> "" Then
            strText = RegExpReplaceTag(strText, "time-reconnect", WAZUH_TIME_RECONNECT)
        End If

        ' What is left of <enrollment>: the three settings that were never about registration.
        If WAZUH_AGENT_NAME <> "" or WAZUH_AGENT_GROUP <> "" or ENROLLMENT_DELAY <> "" Then

            If InStr(strText, "<enrollment>") = 0 Then
                enrollment_list = "    <enrollment>" & vbCrLf
                enrollment_list = enrollment_list & "      <enabled>yes</enabled>" & vbCrLf
                enrollment_list = enrollment_list & "    </enrollment>" & vbCrLf
                enrollment_list = enrollment_list & "  </agent>" & vbCrLf
                strText = Replace(strText, "  </agent>", enrollment_list)
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

        ' Route WAZUH_SSL_VERIFICATION into <agent><ssl><verification_mode>. The only TLS
        ' property left once the token became the sole registration path: nothing writes
        ' <certificate_authorities> at install time any more, since a token install gets its
        ' anchor from the bootstrap and a token-less one is configured by hand.
        If WAZUH_SSL_VERIFICATION <> "" Then
            If WAZUH_SSL_VERIFICATION <> "full" And WAZUH_SSL_VERIFICATION <> "certificate" And WAZUH_SSL_VERIFICATION <> "system" And WAZUH_SSL_VERIFICATION <> "none" Then
                ' Matches Read_Agent_SSL()'s own case-sensitive strcmp (client-config.c): a
                ' value that reads as valid to a human but not to the parser (e.g. 'System')
                ' would install cleanly and only fail at agent startup, instead of here,
                ' where the operator can still see and fix it immediately.
                install_log home_dir, objFSO, "Invalid WAZUH_SSL_VERIFICATION '" & WAZUH_SSL_VERIFICATION & "': must be exactly one of full, certificate, system, none. Leaving <verification_mode> unset."
            Else
                Dim vmCheckText, vmTagRegex, vmSelfClosingRegex, vmReplacementValue
                vmCheckText = StrippedOfComments(strText)
                Set vmTagRegex = New RegExp
                vmTagRegex.Pattern = "<verification_mode(\s*/)?>"
                Set vmSelfClosingRegex = New RegExp
                vmSelfClosingRegex.Pattern = "<verification_mode\s*/>"
                ' RegExp.Replace()'s replacement-string argument treats '$' specially
                ' ($&, $$, $1-$9, $`, $') -- doubling every '$' first, per that same
                ' convention, makes it inert (confirmed empirically: Replace("$&", "$",
                ' "$$") round-trips through RegExp.Replace as the literal text "$&").
                ' WAZUH_SSL_VERIFICATION is enum-validated (full/certificate/system/none) so
                ' this can never actually fire, but applied uniformly with the CA path
                ' below rather than relying on that constraint holding forever.
                vmReplacementValue = Replace(WAZUH_SSL_VERIFICATION, "$", "$$")

                If vmTagRegex.Test(vmCheckText) Then
                    ' Line by line, skipping commented-out lines, same technique as the
                    ' certificate_authorities rewrite below.
                    Dim vmLines, vmLineIdx, vmLine, vmInComment, vmRewritten
                    vmLines = Split(strText, vbCrLf)
                    vmInComment = False
                    vmRewritten = False
                    For vmLineIdx = 0 To UBound(vmLines)
                        vmLine = vmLines(vmLineIdx)
                        If vmInComment Then
                            If InStr(vmLine, "-->") > 0 Then vmInComment = False
                        ElseIf InStr(vmLine, "<!--") > 0 And InStr(vmLine, "-->") > 0 Then
                            ' Self-contained one-line comment ("<!-- ... -->", both on
                            ' this line) -- left untouched, not treated as live: the
                            ' checks below are unanchored substring matches that would
                            ' otherwise match a commented-out example just as well.
                        ElseIf InStr(vmLine, "<!--") > 0 And InStr(vmLine, "-->") = 0 Then
                            vmInComment = True
                        ElseIf (Not vmRewritten) And InStr(vmLine, "<verification_mode>") > 0 And InStr(vmLine, "</verification_mode>") > 0 Then
                            Set re = New RegExp
                            re.Pattern = "<verification_mode>.*</verification_mode>"
                            vmLines(vmLineIdx) = re.Replace(vmLine, "<verification_mode>" & vmReplacementValue & "</verification_mode>")
                            vmRewritten = True
                        ElseIf (Not vmRewritten) And vmSelfClosingRegex.Test(vmLine) Then
                            vmLines(vmLineIdx) = vmSelfClosingRegex.Replace(vmLine, "<verification_mode>" & vmReplacementValue & "</verification_mode>")
                            vmRewritten = True
                        End If
                    Next
                    strText = Join(vmLines, vbCrLf)
                    If Not vmRewritten Then
                        install_log home_dir, objFSO, "Could not pin WAZUH_SSL_VERIFICATION into <ssl><verification_mode>: expected the tag alone on its own line."
                    End If
                ElseIf InStr(vmCheckText, "<ssl>") > 0 Then
                    Dim vmSslLines, vmSslLineIdx, vmSslLine, vmSslInComment, vmSslInserted
                    vmSslLines = Split(strText, vbCrLf)
                    vmSslInComment = False
                    vmSslInserted = False
                    strText = ""
                    For vmSslLineIdx = 0 To UBound(vmSslLines)
                        vmSslLine = vmSslLines(vmSslLineIdx)
                        If vmSslInComment Then
                            If InStr(vmSslLine, "-->") > 0 Then vmSslInComment = False
                        ElseIf InStr(vmSslLine, "<!--") > 0 And InStr(vmSslLine, "-->") = 0 Then
                            vmSslInComment = True
                        End If
                        If vmSslLineIdx > 0 Then strText = strText & vbCrLf
                        strText = strText & vmSslLine
                        If (Not vmSslInserted) And (Not vmSslInComment) And (Trim(vmSslLine) = "<ssl>") Then
                            strText = strText & vbCrLf & "      <verification_mode>" & WAZUH_SSL_VERIFICATION & "</verification_mode>"
                            vmSslInserted = True
                        End If
                    Next
                    If Not vmSslInserted Then
                        install_log home_dir, objFSO, "Could not pin WAZUH_SSL_VERIFICATION into an existing <ssl> block: expected the opening tag alone on its own line."
                    End If
                Else
                    vm_ssl_block = "    <ssl>" & vbCrLf
                    vm_ssl_block = vm_ssl_block & "      <verification_mode>" & WAZUH_SSL_VERIFICATION & "</verification_mode>" & vbCrLf
                    vm_ssl_block = vm_ssl_block & "    </ssl>" & vbCrLf
                    vm_ssl_block = vm_ssl_block & "  </agent>" & vbCrLf
                    strText = Replace(strText, "  </agent>", vm_ssl_block)
                End If
            End If
        End If

        ' Writing the ossec.conf file
        Set objFile = objFSO.OpenTextFile(home_dir & "ossec.conf", ForWriting)
        objFile.WriteLine strText
        objFile.Close

        ' Leave the token where the agent picks it up: w_agent_token_bootstrap() reads it once at
        ' the first start, fetches the CA, checks it against the token's pin, writes the trust
        ' anchor and deletes this file. Same implementation on every platform
        ' (client-agent/src/token_bootstrap.c), reached here through local_start().
        ' SetWazuhPermissions() takes Authenticated Users back off it before this run ends.
        '
        ' token_ok is cleared above if the endpoint could not be written, so this never reports
        ' a manager that was not actually configured.
        If token_ok Then
            ' Created empty, locked down, and only then written -- the order
            ' register_configure_agent.sh uses for the same file, so the credential is never
            ' briefly readable under the install directory's inherited ACL.
            Set objFile = objFSO.CreateTextFile(home_dir & "enrollment_token", True)
            objFile.Close
            Set tokenShell = CreateObject("WScript.Shell")
            tokenShell.run "icacls """ & home_dir & "enrollment_token"" /inheritance:r /grant *S-1-5-18:F /grant *S-1-5-32-544:F /q", 0, True
            Set objFile = objFSO.OpenTextFile(home_dir & "enrollment_token", 2)
            objFile.Write WAZUH_ENROLLMENT_TOKEN
            objFile.Close
            install_log home_dir, objFSO, "Enrollment token stored; the manager was set to '" & token_adr & "' and the trust anchor will be bootstrapped at the first agent start."
        End If

    End If

    ' Outside the refusal guard on purpose: this file is not configuration the deployment
    ' variables touch, and a refused token must not cost the install its internal options. On
    ' Linux the packaging places it, so a refusal there has no equivalent to lose.
    If objFSO.fileExists(home_dir & "ossec.conf") Then

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

        ' Remove Authenticated Users group for ossec.conf, last-ossec.conf, client.keys,
        ' authd.pass and reenroll.secret
        remAuthenticatedUsersPermsConf = "icacls """ & home_dir & "*ossec.conf" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsConf, 0, True

        remAuthenticatedUsersPermsKeys = "icacls """ & home_dir & "client.keys" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsKeys, 0, True

        remAuthenticatedUsersPermsAuthd = "icacls """ & home_dir & "authd.pass" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsAuthd, 0, True

        ' The token carries the enrollment credential, so the blanket Authenticated Users:RX
        ' granted above has to come back off it, the way it does for client.keys just before.
        ' Since #39063 this is the only credential file the installer itself writes: nothing
        ' sets WAZUH_REGISTRATION_PASSWORD any more, so the authd.pass line above now only ever
        ' applies to a file placed by hand or by wazuh-agent-auth.
        '
        ' The file is short-lived either way -- the bootstrap consumes the token at the first
        ' start and unlinks it -- but it is at rest between this install and that start, and on
        ' a machine where the service never starts it stays there.
        remAuthenticatedUsersPermsToken = "icacls """ & home_dir & "enrollment_token" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsToken, 0, True

        ' The per-agent re-enrollment secret (#39064) gets client.keys's treatment, because it has
        ' client.keys's power: it rotates the key of that one agent id. Written by the agent at
        ' enrollment time rather than by this installer, so this only runs against an existing file
        ' on a reinstall or upgrade -- icacls on a missing path is a harmless no-op, and the ACL is
        ' inherited from the (already hardened) install directory when the agent creates it later.
        remAuthenticatedUsersPermsReenroll = "icacls """ & home_dir & "reenroll.secret" & """ /remove *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsReenroll, 0, True

        ' Remove the Authenticated Users group from the tmp directory to avoid
        ' inherited permissions on client.keys and ossec.conf when using win32ui.
        remAuthenticatedUsersPermsTmpDir = "icacls """ & home_dir & "tmp" & """ /remove:g *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsTmpDir, 0, True

        ' Same for the certs directory, which holds the manager's trust anchor: stripped
        ' on the directory because root-ca.pem inherits the grant instead of owning one.
        remAuthenticatedUsersPermsCertsDir = "icacls """ & home_dir & "certs" & """ /remove:g *S-1-5-11 /q"
        WshShell.run remAuthenticatedUsersPermsCertsDir, 0, True

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
' #39064: drop the fleet-wide enrollment password on upgrade. It is one secret that enrols any
' endpoint, left at rest on every one of them; 5.0 replaces it with an enrollment token for the
' first credential and a per-agent re-enrollment secret thereafter. A fresh 5.0 install never
' creates the file, so without this an upgraded host -- the longest-running one in the estate,
' which is exactly where the exposure matters most -- would keep it for ever.
'
' Overwritten before it is deleted, because the bytes are a secret. Best-effort throughout: an
' upgrade must not fail over this.
Public Function RemoveFleetEnrollmentPassword()
    On Error Resume Next
    Dim strArgs, args, home_dir, passPath, agentExe
    Dim fso, shell, rc, objFile, size, i

    ' Read CustomActionData: "[APPLICATIONFOLDER]"
    strArgs = Session.Property("CustomActionData")
    args = Split(strArgs, "/+/")
    home_dir = Replace(args(0), Chr(34), "")
    passPath = home_dir & "authd.pass"
    agentExe = home_dir & "wazuh-agent.exe"

    Set fso = CreateObject("Scripting.FileSystemObject")

    If Not fso.FileExists(passPath) Then
        Set fso = Nothing
        RemoveFleetEnrollmentPassword = 0
        Exit Function
    End If

    ' Overwrite the password in the file's own allocation and unlink it -- what the DEB postinst,
    ' the RPM %post and the macOS postinstall do with `dd conv=notrunc`. The agent does that part:
    ' no write mode reachable from a script host opens a file without truncating it first, so
    ' FileSystemObject would release the secret's bytes and write the zeros into a fresh
    ' allocation. wazuh-agent.exe is already run from this file for --show-token, it is on disk by
    ' now (this action is deferred, After="InstallFiles"), and it ships signed -- which for a
    ' security product's installer is the argument against the other route to OPEN_EXISTING from
    ' VBScript, spawning powershell.exe with -ExecutionPolicy Bypass.
    '
    ' Initialised to "never ran" rather than left Empty, for the same reason DecodeEnrollmentToken
    ' initialises to 127: this file runs under On Error Resume Next, and a Run that throws would
    ' otherwise leave rc equal to 0, which is the one value that means the job is done.
    rc = -1

    If fso.FileExists(agentExe) Then
        Set shell = CreateObject("WScript.Shell")
        rc = shell.Run(Chr(34) & agentExe & Chr(34) & " --shred-enrollment-password", 0, True)
        Set shell = Nothing
    End If

    If rc <> 0 Then
        ' The agent could not be run, or reported that it did not finish. Fall back to what a
        ' script can do on its own: a same-length rewrite, which does NOT overwrite the original
        ' allocation -- worth doing, never worth mistaking for the guarantee above -- and the
        ' delete, which is what actually takes the fleet-wide credential off the endpoint.
        '
        ' Chr(0), not the digit "0": either destroys the plaintext equally well, but every other
        ' path writes NUL (the agent's own overwrite, and `dd if=/dev/zero` in the three POSIX
        ' scripts), and a fallback that leaves a file full of 0x30 reads as a different operation
        ' to anyone who looks at the bytes afterwards.
        If fso.FileExists(passPath) Then
            size = fso.GetFile(passPath).Size
            If size > 0 Then
                Set objFile = fso.OpenTextFile(passPath, 2)
                For i = 1 To size
                    objFile.Write Chr(0)
                Next
                objFile.Close
            End If
            fso.DeleteFile passPath, True
        End If
    End If

    Set fso = Nothing

    ' Always 0: the custom action is Return="check", and a password that could not be removed must
    ' not roll back an upgrade that has otherwise succeeded.
    RemoveFleetEnrollmentPassword = 0
End Function

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
