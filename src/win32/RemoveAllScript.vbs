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


' This function is called only when uninstalling the product.
' Remove everything, but a few specified items.
'
public function removeAll()

   ' Retrieve the parameters
   strArgs = Session.Property("CustomActionData")
   args = Split(strArgs, ",")
   home_dir = Replace(args(0), Chr(34), "") 'APPLICATIONFOLDER

   Set objSFO = CreateObject("Scripting.FileSystemObject")

   If objSFO.fileExists(home_dir & "ossec.conf.save") AND objSFO.fileExists(home_dir & "ossec.conf") Then
      objSFO.DeleteFile(home_dir & "ossec.conf.save")
   End If

   If objSFO.fileExists(home_dir & "client.keys.save") AND objSFO.fileExists(home_dir & "client.keys") Then
      objSFO.DeleteFile(home_dir & "client.keys.save")
   End If

   If objSFO.fileExists(home_dir & "local_internal_options.conf.save") AND objSFO.fileExists(home_dir & "local_internal_options.conf") Then
      objSFO.DeleteFile(home_dir & "local_internal_options.conf.save")
   End If

   If objSFO.fileExists(home_dir & "installer.log.save") AND objSFO.fileExists(home_dir & "installer.log") Then
      objSFO.DeleteFile(home_dir & "installer.log.save")
   End If

   If objSFO.fileExists(home_dir & "ossec.conf") Then
      objSFO.GetFile(home_dir + "\ossec.conf").Name = "ossec.conf.save"
   End If

   If objSFO.fileExists(home_dir & "client.keys") Then
      objSFO.GetFile(home_dir + "\client.keys").Name = "client.keys.save"
   End If

   If objSFO.fileExists(home_dir & "local_internal_options.conf") Then
      objSFO.GetFile(home_dir + "\local_internal_options.conf").Name = "local_internal_options.conf.save"
   End If

   If objSFO.fileExists(home_dir & "installer.log") Then
      objSFO.GetFile(home_dir + "\installer.log").Name = "installer.log.save"
   End If

   If objSFO.folderExists(home_dir) Then
      Set folder = objSFO.GetFolder(home_dir)

      ' Everything in the application's root folder will be deleted.
      ' *BUT*, the files specified here *will not* be deleted
       Dim filesToKeep: filesToKeep = Array("ossec.conf.save", "client.keys.save", _
                                            "local_internal_options.conf.save", "installer.log.save")

      ' Everything in the application's root folder will be deleted.
      ' *BUT*, the subfolders, and the files inside, specified here *will not* be deleted
      Dim subfoldersToKeep: subfoldersToKeep = Array("backup", "upgrade")

      ' Delete the files in the root folder
      For Each f In folder.Files
         name = f.name
         ' Delete the file only if it is not in the list
         If Not isNameInList(name, filesToKeep) Then
            On Error Resume Next
            f.Delete True
         End If
      Next

      ' Delete the subfolders in the root folder
      For Each f In folder.SubFolders
         name = f.name
         ' Delete the file only if it is not in the list
         If Not isNameInList(name, subfoldersToKeep) Then
            On Error Resume Next
            f.Delete True
         End If
      Next

   End If   'objSFO.fileExists

   removeAll = 0

End Function   'removeAll


' Case-insensitive name lookup over a small array. Deliberately avoids
' Scripting.Dictionary: the June 2026 Windows cumulative updates
' (KB5094123 / KB5094128 and siblings) make Dictionary.Add raise a spurious
' error 457 (0x800A01C9), which aborted the whole uninstall.
private function isNameInList(strName, arrNames)
   Dim item
   isNameInList = False
   For Each item In arrNames
      If LCase(strName) = LCase(item) Then
         isNameInList = True
         Exit Function
      End If
   Next
End Function
