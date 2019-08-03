' Script for configuration Windows agent.
' Copyright (C) 2015-2019, Wazuh Inc. <support@wazuh.com>
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

   If objSFO.fileExists(home_dir & "ossec.conf") Then
      objSFO.GetFile(home_dir + "\ossec.conf").Name = "ossec.conf.save"
   End If

   If objSFO.fileExists(home_dir & "client.keys") Then
      objSFO.GetFile(home_dir + "\client.keys").Name = "client.keys.save"
   End If

   If objSFO.fileExists(home_dir & "local_internal_options.conf") Then
      objSFO.GetFile(home_dir + "\local_internal_options.conf").Name = "local_internal_options.conf.save"
   End If

   If objSFO.folderExists(home_dir) Then
      Set folder = objSFO.GetFolder(home_dir)
 
      ' Everything in the application's root folder will be deleted.
      ' *BUT*, the files specified here *will not* be deleted
       Dim filesToKeep: filesToKeep = Array("ossec.conf.save", "client.keys.save", _
                                            "local_internal_options.conf.save")
 
      ' Construct a simple dictionary to check out later whether a file is in
      ' the list or not
      Dim dicFiles: Set dicFiles = CreateObject("Scripting.Dictionary")
      dicFiles.CompareMode = vbTextCompare
      For Each x in filesToKeep
         dicFiles.add x, x
      Next
 
 
      ' Delete the files in the root folder
      For Each f In folder.Files
         name = f.name
         ' Delete the file only if it is not in the list
         If Not dicFiles.Exists(name) Then
            On Error Resume Next
            f.Delete True
         End If
      Next
 
      ' And delete all the subfolders, empty or not
      For Each f In folder.SubFolders
         On Error Resume Next
         f.Delete True
      Next

 
   End If   'objSFO.fileExists
 
   removeAll = 0

End Function   'removeAll


