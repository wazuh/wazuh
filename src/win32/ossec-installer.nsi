!define VERSION "1.0"
!define NAME "Ossec HIDS"
!define /date CDATE "%H:%M:%S %d %b, %Y"


Name "${NAME} Windows Agent v${VERSION}"
Caption "${NAME} Windows Agent Installer"
UninstallCaption "${NAME} Windows Agent Uninstaller"
DirText "${NAME} v${VERSION} Windows Agent Installer."
ComponentText  "${NAME} Windows Agent Installer"
CompletedText "${NAME} Windows Agent Installer is finished"
UninstallText "${NAME} Windows Agent Uninstaller"
BrandingText "Copyright © 2005-2007 Daniel B. Cid"
OutFile "C:\ossec-win32-agent.exe"


InstallDir $PROGRAMFILES\ossec-agent
InstallDirRegKey HKLM "ossec" "Install_Dir"

Function .onInit
    SetOutPath $INSTDIR
    IfFileExists $INSTDIR\ossec.conf 0 +3
    MessageBox MB_OKCANCEL "${NAME} is already installed. We will stop it before continuing." IDOK NoAbort
    Abort
    NoAbort:
    
    ;; Stopping ossec service.
    ExecWait '"net" "stop" "OssecSvc"'  
    
    ;;MessageBox MB_YESNO "This will install. Continue?" IDYES NoAbort
    ;;Abort ; causes installer to quit.
    ;;NoAbort:
FunctionEnd
            

Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

LicenseText "You must agree to this license before installing."
LicenseData "LICENSE.txt"

Section "OSSEC HIDS Windows Agent (required)"

SetOutPath $INSTDIR

ClearErrors

;;IfFileExists $INSTDIR\ossec.conf 0 +3
;;  MessageBox MB_OK "${NAME} is already installed. Make sure to turn it off before you continue."
;;  goto done
;;  
;;  File ossec-default.conf  
;;
;;done:  

File ossec-agent.exe default-ossec.conf manage_agents.exe internal_options.conf setup-windows.exe setup-iis.exe service-start.exe service-stop.exe doc.html rootkit_trojans.txt rootkit_files.txt add-localfile.exe LICENSE.txt
WriteRegStr HKLM SOFTWARE\ossec "Install_Dir" "$INSTDIR"

WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "DisplayName" "OSSEC Hids Agent"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "UninstallString" '"$INSTDIR\uninstall.exe"'
WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoModify" 1
WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoRepair" 1
WriteUninstaller "uninstall.exe"


; Writing version and install information
FileOpen $0 $INSTDIR\VERSION.txt w
IfErrors done
FileWrite $0 "${NAME} v${VERSION} - "
FileWrite $0 "Installed at: ${CDATE}"
FileClose $0
done:


CreateDirectory "$INSTDIR\rids"
CreateDirectory "$INSTDIR\syscheck"
CreateDirectory "$INSTDIR\shared"
Rename "$INSTDIR\rootkit_trojans.txt" "$INSTDIR\shared\rootkit_trojans.txt"
Rename "$INSTDIR\rootkit_files.txt" "$INSTDIR\shared\rootkit_files.txt"
CreateDirectory "$SMPROGRAMS\ossec"
CreateShortCut "$SMPROGRAMS\ossec\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
Delete "$SMPROGRAMS\ossec\Edit.lnk"
CreateShortCut "$SMPROGRAMS\ossec\Edit Config.lnk" "$INSTDIR\ossec.conf" "" "$INSTDIR\ossec.conf" 0
CreateShortCut "$SMPROGRAMS\ossec\Documentation.lnk" "$INSTDIR\doc.html" "" "$INSTDIR\doc.html" 0
CreateShortCut "$SMPROGRAMS\ossec\Start OSSEC.lnk" "$INSTDIR\service-start.exe" "" "$INSTDIR\service-start.exe" 0
CreateShortCut "$SMPROGRAMS\ossec\Stop OSSEC.lnk" "$INSTDIR\service-stop.exe" "" "$INSTDIR\service-stop.exe" 0
CreateShortCut "$SMPROGRAMS\ossec\Import Keys.lnk" "$INSTDIR\manage_agents.exe" "" "$INSTDIR\manage_agents.exe" 0
CreateShortCut "$SMPROGRAMS\ossec\View Logs.lnk" "$INSTDIR\ossec.log" "" "$INSTDIR\ossec.log" 0


; Install in the services 
ExecWait '"$INSTDIR\ossec-agent.exe" install-service'
ExecWait '"$INSTDIR\setup-windows.exe" "$INSTDIR"' 
ExecWait '"C:\Windows\notepad.exe" "$INSTDIR\ossec.conf"'

MessageBox MB_OKCANCEL "Do you wish to start ${NAME} now?" IDOK Startsvc
    Startsvc:
    ;; Starting ossec service.
    ExecWait '"net" "start" "OssecSvc"'
SectionEnd


Section "Uninstall"
  
  ; Stop ossec
  ExecWait '"net" "stop" "OssecSvc"'
  
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

