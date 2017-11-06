SETLOCAL
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin
SET /P VERSION=<..\VERSION

candle.exe -nologo "wazuh-installer.wxs" -out "%VERSION%.wixobj" -ext WixUtilExtension -ext WixUiExtension
light.exe "%VERSION%.wixobj" -out "%VERSION%.msi"  -ext WixUtilExtension -ext WixUiExtension

% signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "%VERSION%.msi" %
