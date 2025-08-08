; include Modern UI
!include "MUI.nsh"

; standard NSIS includes
!include "LogicLib.nsh"
!include "WinVer.nsh"

; include nsProcess
!addincludedir "nsProcess"
!addplugindir "nsProcess"
!include "nsProcess.nsh"

; include SimpleSC
!addplugindir "SimpleSC"

; include GetTime
!include "FileFunc.nsh"
!insertmacro GetTime

; general
!define MUI_ICON install.ico
!define MUI_UNICON uninstall.ico
!define VERSION "4.10.3"
!define REVISION "41031"
!define NAME "Wazuh"
!define SERVICE "WazuhSvc"

; output file
!ifndef OutFile
    !define OutFile "wazuh-agent-${VERSION}.exe"
!endif

Var is_upgrade

Name "${NAME} Windows Agent v${VERSION}"
BrandingText "Copyright (C) 2015, Wazuh Inc."
OutFile "${OutFile}"

VIProductVersion "4.10.3.0"
VIAddVersionKey ProductName "${NAME}"
VIAddVersionKey CompanyName "Wazuh Inc."
VIAddVersionKey LegalCopyright "2023 - Wazuh Inc."
VIAddVersionKey FileDescription "Wazuh Agent installer"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey InternalName "Wazuh Agent"
VIAddVersionKey OriginalFilename "${OutFile}"

InstallDir "$PROGRAMFILES\ossec-agent"
InstallDirRegKey HKLM Software\OSSEC ""

; show (un)installation details
ShowInstDetails show
ShowUninstDetails show

; do not close details pages immediately
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

; interface settings
!define MUI_ABORTWARNING

; pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the install of ${Name}.\r\n\r\nClick next to continue."
!define MUI_FINISHPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_RUN "$INSTDIR\win32ui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Run Agent manager"

; page for choosing components
!define MUI_COMPONENTSPAGE_TEXT_TOP "Select the options you want to be executed. Click next to continue."
!define MUI_COMPONENTSPAGE_NODESC

; pages to display to user
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; these have to be defined again to work with the uninstall pages
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; languages
!insertmacro MUI_LANGUAGE "English"

; function to stop OSSEC service if running
Function .onInit
    StrCpy $is_upgrade "no"

    ; stop service
    SimpleSC::ExistsService "${SERVICE}"
    Pop $0
    ${If} $0 = 0
        SimpleSC::ServiceIsStopped "${SERVICE}"
        Pop $0
        Pop $1
        ${If} $0 = 0
            ${If} $1 <> 1
                MessageBox MB_OKCANCEL "${NAME} is already installed and the ${SERVICE} service is running. \
                    It will be stopped before continuing." /SD IDOK IDOK ServiceStop
                SetErrorLevel 2
                Abort

                ServiceStop:
                    SimpleSC::StopService "${SERVICE}" 1 30
                    Pop $0
                    ${If} $0 <> 0
                        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                            Failure stopping the ${SERVICE} service ($0).$\r$\n$\r$\n\
                            Click Abort to stop the installation,$\r$\n\
                            Retry to try again, or$\r$\n\
                            Ignore to skip this file." /SD IDABORT IDIGNORE ServiceStopped IDRETRY ServiceStop

                        SetErrorLevel 2
                        Abort
                    ${Else}
                        StrCpy $is_upgrade "yes"
                    ${EndIf}
            ${EndIf}
        ${Else}
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure checking status of the ${SERVICE} service ($0).$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ServiceStopped IDRETRY ServiceStop

            SetErrorLevel 2
            Abort
        ${EndIf}
    ${EndIf}
    ServiceStopped:
FunctionEnd

; main install section
Section "Wazuh Agent (required)" MainSec
    ; set install type and cwd
    SectionIn RO
    SetOutPath $INSTDIR

    ; clear any errors
    ClearErrors

    ; use real date modified times
    SetDateSave off

    ; overwrite existing files
    SetOverwrite on

    ; remove diff and state files when upgrading

    Push "$INSTDIR\queue\diff\local"
    Push "last-entry"
    Push $0
    GetFunctionAddress $0 "RmFiles"
    Exch $0
    Call FindFiles

    ; create necessary directories
    CreateDirectory "$INSTDIR\bookmarks"
    CreateDirectory "$INSTDIR\logs"
    CreateDirectory "$INSTDIR\rids"
    CreateDirectory "$INSTDIR\syscheck"
    CreateDirectory "$INSTDIR\shared"
    CreateDirectory "$INSTDIR\active-response"
    CreateDirectory "$INSTDIR\active-response\bin"
    CreateDirectory "$INSTDIR\tmp"
    CreateDirectory "$INSTDIR\queue"
    CreateDirectory "$INSTDIR\queue\diff"
    CreateDirectory "$INSTDIR\queue\fim"
    CreateDirectory "$INSTDIR\queue\fim\db"
    CreateDirectory "$INSTDIR\queue\syscollector"
    CreateDirectory "$INSTDIR\queue\syscollector\db"
    CreateDirectory "$INSTDIR\queue\logcollector"
    CreateDirectory "$INSTDIR\incoming"
    CreateDirectory "$INSTDIR\upgrade"
    CreateDirectory "$INSTDIR\wodles"
    CreateDirectory "$INSTDIR\ruleset\"
    CreateDirectory "$INSTDIR\ruleset\sca"

    ; install files
    File wazuh-agent.exe
    File wazuh-agent-eventchannel.exe
    File default-ossec.conf
    File manage_agents.exe
    File /oname=win32ui.exe os_win32ui.exe
    File internal_options.conf
    File default-local_internal_options.conf
    File setup-windows.exe
    File setup-syscheck.exe
    File setup-iis.exe
    File doc.html
    File favicon.ico
    File /oname=shared\rootkit_trojans.txt ..\..\ruleset\rootcheck\db\rootkit_trojans.txt
    File /oname=shared\rootkit_files.txt ..\..\ruleset\rootcheck\db\rootkit_files.txt
    File LICENSE.txt
    File /oname=shared\win_applications_rcl.txt ..\..\ruleset\rootcheck\db\win_applications_rcl.txt
    File /oname=shared\win_malware_rcl.txt ..\..\ruleset\rootcheck\db\win_malware_rcl.txt
    File /oname=shared\win_audit_rcl.txt ..\..\ruleset\rootcheck\db\win_audit_rcl.txt
    File /oname=help.txt help_win.txt
    File vista_sec.txt
    File /oname=active-response\bin\route-null.exe route-null.exe
    File /oname=active-response\bin\restart-wazuh.exe restart-wazuh.exe
    File /oname=active-response\bin\netsh.exe netsh.exe
    File /oname=libwinpthread-1.dll libwinpthread-1.dll
    File /oname=libgcc_s_dw2-1.dll libgcc_s_dw2-1.dll
    File /oname=libstdc++-6.dll libstdc++-6.dll
    File agent-auth.exe
    File /oname=wpk_root.pem ..\..\etc\wpk_root.pem
    File /oname=libwazuhext.dll ..\libwazuhext.dll
    File /oname=libwazuhshared.dll ..\libwazuhshared.dll
    File /oname=dbsync.dll ..\shared_modules\dbsync\build\bin\dbsync.dll
    File /oname=rsync.dll ..\shared_modules\rsync\build\bin\rsync.dll
    File /oname=sysinfo.dll ..\data_provider\build\bin\sysinfo.dll
    File /oname=syscollector.dll ..\wazuh_modules\syscollector\build\bin\syscollector.dll
    File /oname=libfimdb.dll ..\syscheckd/build/bin/libfimdb.dll
    File /oname=queue\syscollector\norm_config.json ..\wazuh_modules\syscollector\norm_config.json
    File VERSION
    File REVISION

    ; Create empty file active-responses.log
    FileOpen $0 "$INSTDIR\active-response\active-responses.log" w
    FileClose $0

    ; use appropriate version of "wazuh-agent.exe"
    ${If} ${AtLeastWinVista}
        Delete "$INSTDIR\wazuh-agent.exe"
        Rename "$INSTDIR\wazuh-agent-eventchannel.exe" "$INSTDIR\wazuh-agent.exe"
    ${Else}
        Delete "$INSTDIR\wazuh-agent-eventchannel.exe"
    ${Endif}

    ; write registry keys
    WriteRegStr HKLM SOFTWARE\ossec "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayName" "${NAME} Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "Publisher" "Wazuh, Inc."
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "DisplayIcon" '"$INSTDIR\favicon.ico"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "HelpLink" "https://wazuh.com"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "URLInfoAbout" "https://wazuh.com"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "UninstallString" '"$INSTDIR\uninstall.exe"'
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "EstimatedSize" "$0"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC" "NoRepair" 1
    WriteUninstaller "uninstall.exe"

    ; get current local time
    ${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
    var /global CURRENTTIME
    StrCpy $CURRENTTIME "$2-$1-$0 $4:$5:$6"

    ; create log file
    LogInstall:
        ClearErrors
        IfFileExists "$INSTDIR\ossec.log" LogComplete
        FileOpen $0 "$INSTDIR\ossec.log" w
        FileClose $0
        IfErrors LogError LogComplete
    LogError:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
            Failure creating the ossec.log file.$\r$\n$\r$\n\
            File:$\r$\n$\r$\n$INSTDIR\ossec.log$\r$\n$\r$\n\
            Click Abort to stop the installation,$\r$\n\
            Retry to try again, or$\r$\n\
            Ignore to skip this file." /SD IDABORT IDIGNORE LogComplete IDRETRY LogInstall

        SetErrorLevel 2
        Abort
    LogComplete:
        ClearErrors

    ; rename local_internal_options.conf if it does not already exist
    ConfInstallInternal:
        ClearErrors
        IfFileExists "$INSTDIR\local_internal_options.conf" ConfPresentInternal
        Rename "$INSTDIR\default-local_internal_options.conf" "$INSTDIR\local_internal_options.conf"
        IfErrors ConfErrorInternal ConfPresentInternal
    ConfErrorInternal:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
            Failure renaming configuration file.$\r$\n$\r$\n\
            From:$\r$\n$\r$\n\
            $INSTDIR\default-local_internal_options.conf$\r$\n$\r$\n\
            To:$\r$\n$\r$\n\
            $INSTDIR\local_internal_options.conf$\r$\n$\r$\n\
            Click Abort to stop the installation,$\r$\n\
            Retry to try again, or$\r$\n\
            Ignore to skip this file." /SD IDABORT IDIGNORE ConfPresentInternal IDRETRY ConfInstallInternal

        SetErrorLevel 2
        Abort
    ConfPresentInternal:
        ClearErrors

    ; rename ossec.conf if it does not already exist
    ConfInstallOSSEC:
        ClearErrors
        IfFileExists "$INSTDIR\ossec.conf" ConfPresentOSSEC
            Rename "$INSTDIR\default-ossec.conf" "$INSTDIR\ossec.conf"
        IfErrors ConfErrorOSSEC ConfPresentOSSEC
    ConfErrorOSSEC:
        MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
            Failure renaming configuration file.$\r$\n$\r$\n\
            From:$\r$\n$\r$\n\
            $INSTDIR\default-ossec.conf$\r$\n$\r$\n\
            To:$\r$\n$\r$\n\
            $INSTDIR\ossec.conf$\r$\n$\r$\n\
            Click Abort to stop the installation,$\r$\n\
            Retry to try again, or$\r$\n\
            Ignore to skip this file." /SD IDABORT IDIGNORE ConfPresentOSSEC IDRETRY ConfInstallOSSEC

        SetErrorLevel 2
        Abort
    ConfPresentOSSEC:
        ClearErrors

    ; handle shortcuts
    ; https://nsis.sourceforge.net/Shortcuts_removal_fails_on_Windows_Vista
    SetShellVarContext all

    ; remove shortcuts
    Delete "$SMPROGRAMS\OSSEC\Edit.lnk"
    Delete "$SMPROGRAMS\OSSEC\Uninstall.lnk"
    Delete "$SMPROGRAMS\OSSEC\Documentation.lnk"
    Delete "$SMPROGRAMS\OSSEC\Edit Config.lnk"
    Delete "$SMPROGRAMS\OSSEC\*.*"
    RMDir "$SMPROGRAMS\OSSEC"

    ; create shortcuts
    CreateDirectory "$SMPROGRAMS\OSSEC"
    CreateShortCut "$SMPROGRAMS\OSSEC\Manage Agent.lnk" "$INSTDIR\win32ui.exe" "" "$INSTDIR\win32ui.exe" 0
    CreateShortCut "$SMPROGRAMS\OSSEC\Documentation.lnk" "$INSTDIR\doc.html" "" "$INSTDIR\doc.html" 0
    CreateShortCut "$SMPROGRAMS\OSSEC\Edit Config.lnk" "$INSTDIR\ossec.conf" "" "$INSTDIR\ossec.conf" 0
    CreateShortCut "$SMPROGRAMS\OSSEC\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0

    ; install OSSEC service
    ServiceInstall:
        nsExec::ExecToLog '"$INSTDIR\wazuh-agent.exe" install-service'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure setting up the ${SERVICE} service.$\r$\n$\r$\n\
                Check the details for information about the error.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ServiceInstallComplete IDRETRY ServiceInstall

            SetErrorLevel 2
            Abort
        ${EndIf}
    ServiceInstallComplete:

    ; install files
    Setup:
        nsExec::ExecToLog '"$INSTDIR\setup-windows.exe" "$INSTDIR"'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure running setup-windows.exe.$\r$\n$\r$\n\
                Check the details for information about the error.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE SetupComplete IDRETRY Setup

            SetErrorLevel 2
            Abort
        ${EndIf}


    ${If} $is_upgrade == "yes"
        Goto StartService
    ${Else}
        Goto SetupComplete
    ${EndIf}

    StartService:
        SimpleSC::ExistsService "${SERVICE}"
        Pop $0
        ${If} $0 = 0
            ; StartService [name_of_service] [arguments] [timeout]
            SimpleSC::StartService "${SERVICE}" "" 30
            Pop $0
            ${If} $0 <> 0
                MessageBox MB_RETRYCANCEL  "$\r$\n\
                    Failure starting the ${SERVICE} ($0).$\r$\n$\r$\n\
                    Click Cancel to finish the installation without starting the service,$\r$\n\
                    Click Retry to try again." /SD IDABORT IDCANCEL SetupComplete IDRETRY StartService
            ${EndIf}
        ${Else}
            MessageBox MB_OK  "$\r$\n\
                Service not found ${SERVICE} ($0).$\r$\n$\r$\n\
                Click Cancel to stop the installation,$\r$\n\
                Click Retry to try again." /SD IDABORT IDCANCEL SetupComplete IDRETRY StartService
            SetErrorLevel 2
            Abort
        ${EndIf}

    SetupComplete:

SectionEnd

; add IIS logs
Section "Scan and monitor IIS logs (recommended)" IISLogs
    nsExec::ExecToLog '"$INSTDIR\setup-iis.exe" "$INSTDIR"'
SectionEnd

; Disable integrity checking
Section /o "Disable integrity checking (not recommended)" IntChecking
    nsExec::ExecToLog '"$INSTDIR\setup-syscheck.exe" "$INSTDIR" "disable"'
SectionEnd

; uninstall section
Section "Uninstall"
    ; uninstall the services
    ; this also stops the service as well so it should be done early
    ServiceUninstall:
        nsExec::ExecToLog '"$INSTDIR\wazuh-agent.exe" uninstall-service'
        Pop $0
        ${If} $0 <> 1
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Failure uninstalling the ${SERVICE} service.$\r$\n$\r$\n\
                Check the details for information about the error.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ServiceUninstallComplete IDRETRY ServiceUninstall

            SetErrorLevel 2
            Abort
        ${EndIf}
    ServiceUninstallComplete:

    ; make sure manage_agents.exe is not running
    ManageAgents:
        ${nsProcess::FindProcess} "manage_agents.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Found manage_agents.exe is still running.$\r$\n$\r$\n\
                Please close it before continuing.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE ManageAgentsClosed IDRETRY ManageAgents

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    ManageAgentsClosed:

    ; make sure win32ui.exe is not running
    win32ui:
        ${nsProcess::FindProcess} "win32ui.exe" $0
        ${If} $0 = 0
            MessageBox MB_ABORTRETRYIGNORE|MB_ICONSTOP "$\r$\n\
                Found win32ui.exe is still running.$\r$\n$\r$\n\
                Please close it before continuing.$\r$\n$\r$\n\
                Click Abort to stop the installation,$\r$\n\
                Retry to try again, or$\r$\n\
                Ignore to skip this file." /SD IDABORT IDIGNORE win32uiClosed IDRETRY win32ui

            ${nsProcess::Unload}
            SetErrorLevel 2
            Abort
        ${EndIf}
    win32uiClosed:

    ; unload nsProcess
    ${nsProcess::Unload}

    ; remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OSSEC"
    DeleteRegKey HKLM SOFTWARE\OSSEC

    ; remove files and uninstaller
    Delete "$INSTDIR\wazuh-agent.exe"
    Delete "$INSTDIR\agent-auth.exe"
    Delete "$INSTDIR\manage_agents.exe"
    Delete "$INSTDIR\ossec.conf"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\*"
    Delete "$INSTDIR\bookmarks\*"
    Delete "$INSTDIR\logs\*"
    Delete "$INSTDIR\rids\*"
    Delete "$INSTDIR\syscheck\*"
    Delete "$INSTDIR\shared\*"
    Delete "$INSTDIR\active-response\bin\*"
    Delete "$INSTDIR\active-response\*"
    Delete "$INSTDIR\tmp\*"
    Delete "$INSTDIR\incoming\*"
    Delete "$INSTDIR\wodles\*"
    Delete "$INSTDIR\queue\syscollector\db\*"
    Delete "$INSTDIR\queue\syscollector\*"
    Delete "$INSTDIR\queue\fim\db\*"
    Delete "$INSTDIR\queue\fim\*"
    Delete "$INSTDIR\ruleset\sca\*"
    Delete "$INSTDIR\ruleset\*"

    ; remove shortcuts
    SetShellVarContext all
    Delete "$SMPROGRAMS\OSSEC\*.*"
    Delete "$SMPROGRAMS\OSSEC\*"
    RMDir "$SMPROGRAMS\OSSEC"

    ; remove directories used
    RMDir "$INSTDIR\shared"
    RMDir "$INSTDIR\syscheck"
    RMDir "$INSTDIR\bookmarks"
    RMDir "$INSTDIR\logs"
    RMDir "$INSTDIR\rids"
    RMDir "$INSTDIR\active-response\bin"
    RMDir "$INSTDIR\active-response"
    RMDir "$INSTDIR\tmp"
    RMDir /r "$INSTDIR\queue\diff"
    RMDir /r "$INSTDIR\queue\logcollector"
    RMDir "$INSTDIR\incoming"
    RMDir /r "$INSTDIR\upgrade"
    RMDir /r "$INSTDIR\queue\syscollector"
    RMDir /r "$INSTDIR\queue\fim"
    RMDir "$INSTDIR\queue"
    RMDir "$INSTDIR\wodles"
    RMDir "$INSTDIR\ruleset\sca"
    RMDir "$INSTDIR\ruleset"
    RMDir "$INSTDIR"
SectionEnd

Function FindFiles
  Exch $R5 # callback function
  Exch
  Exch $R4 # file name
  Exch 2
  Exch $R0 # directory
  Push $R1
  Push $R2
  Push $R3
  Push $R6

  Push $R0 # first dir to search

  StrCpy $R3 1

  nextDir:
    Pop $R0
    IntOp $R3 $R3 - 1
    ClearErrors
    FindFirst $R1 $R2 "$R0\*.*"
    nextFile:
      StrCmp $R2 "." gotoNextFile
      StrCmp $R2 ".." gotoNextFile

      StrCmp $R2 $R4 0 isDir
        Call $R5
        Pop $R6
        StrCmp $R6 "stop" 0 isDir
          loop:
            StrCmp $R3 0 done
            Pop $R0
            IntOp $R3 $R3 - 1
            Goto loop

      isDir:
        IfFileExists "$R0\$R2\*.*" 0 gotoNextFile
          IntOp $R3 $R3 + 1
          Push "$R0\$R2"

  gotoNextFile:
    FindNext $R1 $R2
    IfErrors 0 nextFile

  done:
    FindClose $R1
    StrCmp $R3 0 0 nextDir

  Pop $R6
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
  Pop $R5
  Pop $R4
FunctionEnd

Function RmFiles
 StrCpy $1 $R0
 Push $1 ; route dir
 Push $2
 Push $2

  FindFirst $3 $2 "$1\*.*"
  IfErrors Exit

  Top:
   StrCmp $2 "." Next
   StrCmp $2 ".." Next
   StrCmp $2 "last-entry" Next
   IfFileExists "$1\$2\*.*" Next
    Delete "$1\$2"

   Next:
    ClearErrors
    FindNext $3 $2
    IfErrors Exit
   Goto Top

  Exit:
  FindClose $2

 Pop $3
 Pop $2
 Pop $1
 Push "go"
FunctionEnd
