SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin

signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "agent-auth.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "manage_agents.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "ossec-agent.exe"
signtool.exe sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "os_win32ui.exe"