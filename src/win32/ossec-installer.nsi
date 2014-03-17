;--------------------------------
;Include Modern UI

!include "MUI.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"

;--------------------------------
;General

!ifndef OutFile
 !define OutFile "ossec-win32-agent.exe"
!endif

!define MUI_ICON favicon.ico
!define MUI_UNICON ossec-uninstall.ico
!define VERSION "2.7.1"
!define NAME "OSSEC HIDS"
!define /date CDATE "%b %d %Y at %H:%M:%S"

Name "${NAME} Windows Agent v${VERSION}"
BrandingText "Copyright (C) 2003 - 2013 Trend Micro Inc."
OutFile "${OutFile}"

InstallDir "$PROGRAMFILES\ossec-agent"
InstallDirRegKey HKLM Software\OSSEC ""

; show installation details
ShowInstDetails show

; do not close details pages immediately
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

;--------------------------------
;Interface Settings

!define MUI_ABORTWARNING

;--------------------------------
;Pages
  !define MUI_WELCOMEPAGE_TITLE_3LINES
  !define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the install of ${Name}.\r\n\r\nClick next to continue."
  !define MUI_FINISHPAGE_TITLE_3LINES
  !define MUI_FINISHPAGE_RUN "$INSTDIR\win32ui.exe"
  !define MUI_FINISHPAGE_RUN_TEXT "Run OSSEC Agent Manager"

  ; Page for choosing components.
  !define MUI_COMPONENTSPAGE_TEXT_TOP "Select the options you want to be executed. Click next to continue."
  !define MUI_COMPONENTSPAGE_NODESC

  !insertmacro MUI_PAGE_WELCOME
  !insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH

  ; These have to be defined again to work with the uninstall pages
  !define MUI_WELCOMEPAGE_TITLE_3LINES
  !define MUI_FINISHPAGE_TITLE_3LINES
  !insertmacro MUI_UNPAGE_WELCOME
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_UNPAGE_FINISH

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Function to stop OSSEC service if running

Function .onInit
    IfFileExists $INSTDIR\ossec.conf 0 NoAbort
    MessageBox MB_OKCANCEL "${NAME} is already installed. It will be stopped before continuing." /SD IDOK IDOK NoAbort
    Abort
    NoAbort:

   ;; Stopping ossec service.
   nsExec::ExecToLog '"net" "stop" "OssecSvc"'
FunctionEnd

;--------------------------------
;Main install section

Section "OSSEC Agent (required)" MainSec

SectionIn RO
SetOutPath $INSTDIR

ClearErrors


; overwrite existing files
SetOverwrite on

; create necessary directories
CreateDirectory "$INSTDIR\bookmarks"
CreateDirectory "$INSTDIR\rids"
CreateDirectory "$INSTDIR\syscheck"
CreateDirectory "$INSTDIR\shared"
CreateDirectory "$INSTDIR\active-response"
CreateDirectory "$INSTDIR\active-response\bin"

; install files
File ossec-lua.exe 
File ossec-luac.exe 
File ossec-agent.exe
File ossec-agent-eventchannel.exe
File default-ossec.conf
File manage_agents.exe
File /oname=win32ui.exe os_win32ui.exe
File ossec-rootcheck.exe
File internal_options.conf
File setup-windows.exe
File setup-syscheck.exe
File setup-iis.exe
File doc.html
File /oname=shared\rootkit_trojans.txt rootkit_trojans.txt
File /oname=shared\rootkit_files.txt rootkit_files.txt
File add-localfile.exe
File LICENSE.txt
File /oname=shared\win_applications_rcl.txt rootcheck\db\win_applications_rcl.txt
File /oname=shared\win_malware_rcl.txt rootcheck\db\win_malware_rcl.txt
File /oname=shared\win_audit_rcl.txt rootcheck\db\win_audit_rcl.txt
File help.txt
File vista_sec.csv
File /oname=active-response\bin\route-null.cmd route-null.cmd
File /oname=active-response\bin\restart-ossec.cmd restart-ossec.cmd

; Use appropriate version of "ossec-agent.exe"
${If} ${AtLeastWinVista}
  Delete "$INSTDIR\ossec-agent.exe"
  Rename "$INSTDIR\ossec-agent-eventchannel.exe" "$INSTDIR\ossec-agent.exe"
${Else}
  Delete "$INSTDIR\ossec-agent-eventchannel.exe"
${Endif}

WriteRegStr HKLM SOFTWARE\ossec "Install_Dir" "$INSTDIR"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayName" "${NAME} ${VERSION}"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayVersion" "${VERSION}"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayIcon" "${MUI_ICON}"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "HelpLink" "http://www.ossec.net/main/support/"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "URLInfoAbout" "http://www.ossec.net"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "UninstallString" '"$INSTDIR\uninstall.exe"'
WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoModify" 1
WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ossec" "NoRepair" 1
WriteUninstaller "uninstall.exe"

; Writing version and install information
FileOpen $0 $INSTDIR\VERSION.txt w
IfErrors done
FileWrite $0 "${NAME} v${VERSION} - "
FileWrite $0 "Installed on ${CDATE}"
FileClose $0
done:

Delete "$SMPROGRAMS\OSSEC\Edit.lnk"
Delete "$SMPROGRAMS\OSSEC\Uninstall.lnk"
Delete "$SMPROGRAMS\OSSEC\Documentation.lnk"
Delete "$SMPROGRAMS\OSSEC\Edit Config.lnk"
Delete "$SMPROGRAMS\OSSEC\*.*"

; rename ossec.conf if it does not
; already exist
ConfInstall:
    ClearErrors
    IfFileExists "$INSTDIR\ossec.conf" ConfPresent
    Rename "$INSTDIR\default-ossec.conf" "$INSTDIR\ossec.conf"
IfErrors ConfError ConfPresent
ConfError:
    MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\nFailed to rename file.$\r$\n$\r$\nFrom:$\r$\n$\r$\n$INSTDIR\default-ossec.conf\
        $\r$\n$\r$\nTo:$\r$\n$\r$\n$INSTDIR\ossec.conf$\r$\n$\r$\nClick Abort sto stop the installation,$\r$\nRetry to try again, or$\r$\n\
        Ignore to skip this file." /SD IDABORT IDIGNORE ConfPresent IDRETRY ConfInstall

    SetErrorLevel 2
    Abort
ConfPresent:
    ClearErrors

; Handle shortcuts
; http://nsis.sourceforge.net/Shortcuts_removal_fails_on_Windows_Vista
SetShellVarContext all

; Remove start menu entry.
RMDir "$SMPROGRAMS\OSSEC"

; Creating start menu directory
CreateDirectory "$SMPROGRAMS\OSSEC"
CreateShortCut "$SMPROGRAMS\OSSEC\Manage Agent.lnk" "$INSTDIR\win32ui.exe" "" "$INSTDIR\win32ui.exe" 0
CreateShortCut "$SMPROGRAMS\OSSEC\Documentation.lnk" "$INSTDIR\doc.html" "" "$INSTDIR\doc.html" 0
CreateShortCut "$SMPROGRAMS\OSSEC\Edit Config.lnk" "$INSTDIR\ossec.conf" "" "$INSTDIR\ossec.conf" 0
CreateShortCut "$SMPROGRAMS\OSSEC\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0

; Install in the services  (perhaps it would be better to use a plug-in here?)
nsExec::ExecToLog '"$INSTDIR\ossec-agent.exe" install-service'
nsExec::ExecToLog '"$INSTDIR\setup-windows.exe" "$INSTDIR"'

SectionEnd

Section "Scan and monitor IIS logs (recommended)" IISLogs

nsExec::ExecToLog '"$INSTDIR\setup-iis.exe" "$INSTDIR"'

SectionEnd

Section "Enable integrity checking (recommended)" IntChecking

nsExec::ExecToLog '"$INSTDIR\setup-syscheck.exe" "$INSTDIR" "enable"'

SectionEnd

;--------------------------------
;Uninstall section
Section "Uninstall"

  ;Need a step to check for a running agent manager, otherwise it and the INSTDIR directory will not be removed.

  ; Stop ossec. Perhaps we should look for an exit status here. Also, may be a good place to use a plug-in.
  nsExec::ExecToLog '"net" "stop" "OssecSvc"'

  ; Uninstall from the services. Again, maybe use a plugin here.
  nsExec::ExecToLog '"$INSTDIR\ossec-agent.exe" uninstall-service'

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC"
  DeleteRegKey HKLM SOFTWARE\OSSEC

  ; Remove files and uninstaller. There have been instances where the ossec-agent directory and executable is left. Why?
  Delete "$INSTDIR\ossec-agent.exe"
  Delete "$INSTDIR\ossec-lua.exe"
  Delete "$INSTDIR\ossec-luac.exe"
  Delete "$INSTDIR\manage_agents.exe"
  Delete "$INSTDIR\ossec.conf"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\*"
  Delete "$INSTDIR\bookmarks\*"
  Delete "$INSTDIR\rids\*"
  Delete "$INSTDIR\syscheck\*"
  Delete "$INSTDIR\shared\*"
  Delete "$INSTDIR\active-response\bin\*"
  Delete "$INSTDIR\active-response\*"
  Delete "$INSTDIR"

  ; Remove shortcuts, if any
  SetShellVarContext all
  Delete "$SMPROGRAMS\OSSEC\*.*"
  Delete "$SMPROGRAMS\OSSEC\*"

  ; Remove directories used
  RMDir "$SMPROGRAMS\OSSEC"
  RMDir "$INSTDIR\shared"
  RMDir "$INSTDIR\syscheck"
  RMDir "$INSTDIR\bookmarks"
  RMDir "$INSTDIR\rids"
  RMDir "$INSTDIR\active-response\bin"
  RMDir "$INSTDIR\active-response"
  RMDir "$INSTDIR"

SectionEnd
