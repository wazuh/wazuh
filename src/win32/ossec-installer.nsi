!define VERSION "0.8BETA"
!define NAME "Ossec HIDS"

Name "${NAME} Windows Agent v${VERSION}"
Caption "${NAME} Windows Agent Installer"
UninstallCaption "${NAME} Windows Agent Uninstaller"
DirText "${NAME} Windows Agent Installer"
ComponentText  "${NAME} Windows Agent Installer"
CompletedText "${NAME} Windows Agent Installer is finished"
UninstallText "${NAME} Windows Agent Uninstaller"
BrandingText " "
OutFile "C:\ossec-win32-agent.exe"


InstallDir $PROGRAMFILES\ossec-agent
InstallDirRegKey HKLM "ossec" "Install_Dir"

Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles


Section "OSSEC HIDS Windows Agent (required)"

SetOutPath $INSTDIR
  
File ossec-agent.exe ossec.conf manage_agents.exe iis-logs.bat
WriteRegStr HKLM SOFTWARE\ossec "Install_Dir" "$INSTDIR"

WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "DisplayName" "OSSEC Hids Agent"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "UninstallString" '"$INSTDIR\uninstall.exe"'
WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoModify" 1
WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoRepair" 1
WriteUninstaller "uninstall.exe"

CreateDirectory "$SMPROGRAMS\ossec"
CreateShortCut "$SMPROGRAMS\ossec\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
CreateShortCut "$SMPROGRAMS\ossec\Edit.lnk" "$INSTDIR\ossec.conf" "" "$INSTDIR\ossec.conf" 0
CreateShortCut "$SMPROGRAMS\ossec\Documentation.lnk" "http://www.ossec.net/en/manual.html" "" "http://www.ossec.net/en/manual.html" 0

; Install in the services 
Exec '$INSTDIR\iis-logs.bat'
Exec '"$INSTDIR\ossec-agent.exe" install-service'
ExecWait '"C:\WINDOWS\notepad.exe" "$INSTDIR\ossec.conf"'
ExecWait '$INSTDIR\manage_agents.exe'

SectionEnd


Section "Uninstall"
  
  ; Uninstall from the services
  Exec '"$INSTDIR\ossec-agent.exe" uninstall-service'

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec"
  DeleteRegKey HKLM SOFTWARE\ossec

  ; Remove files and uninstaller
  Delete "$INSTDIR\ossec-agent.exe"
  Delete "$INSTDIR\manage_agents.exe"
  Delete "$INSTDIR\ossec.conf"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\*"
  Delete "$INSTDIR"

  ; Remove shortcuts, if any
  Delete "$SMPROGRAMS\ossec\*.*"

  ; Remove directories used
  RMDir "$SMPROGRAMS\ossec"
  RMDir "$INSTDIR"

SectionEnd

