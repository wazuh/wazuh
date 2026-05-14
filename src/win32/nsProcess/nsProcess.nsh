!define nsProcess::FindProcess `!insertmacro nsProcess::FindProcess`

!macro nsProcess::FindProcess _FILE _ERR
	nsProcess::_FindProcess /NOUNLOAD `${_FILE}`
	Pop ${_ERR}
!macroend


!define nsProcess::KillProcess `!insertmacro nsProcess::KillProcess`

!macro nsProcess::KillProcess _FILE _ERR
	nsProcess::_KillProcess /NOUNLOAD `${_FILE}`
	Pop ${_ERR}
!macroend


!define nsProcess::Unload `!insertmacro nsProcess::Unload`

!macro nsProcess::Unload
	nsProcess::_Unload
!macroend
