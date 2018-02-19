SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "add-localfile.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "agent-auth.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "manage_agents.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "ossec-agent.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "os_win32ui.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "ossec-agent-eventchannel.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "ossec-lua.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "ossec-luac.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "ossec-rootcheck.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "setup-iis.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "setup-syscheck.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "setup-windows.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "wazuh-agent-3.2.0.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "InstallerScripts.vbs"

pause
