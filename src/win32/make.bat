echo Making windows agent

"C:\MinGW\bin\windres.exe" -i icofile.rc -o icon.o
"C:\MinGW\bin\gcc.exe" -o "ossec-agent" -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 -DOSSECHIDS icon.o os_regex/*.c os_net/*.c os_xml/*.c zlib-1.2.3/*.c config/*.c shared/*.c os_execd/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/sha1/*.c os_crypto/md5_sha1/*.c os_crypto/shared/*.c rootcheck/*.c *.c -I. -Iheaders/ -lwsock32
"C:\MinGW\bin\gcc.exe" -o "ossec-rootcheck" -Wall  -DARGV0=\"ossec-rootcheck\" -DCLIENT -DWIN32 icon.o os_regex/*.c os_net/*.c os_xml/*.c config/*.c shared/*.c win_service.c rootcheck/*.c -Iheaders/ -I. -lwsock32
"C:\MinGW\bin\gcc.exe" -o "manage_agents" -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 -DMA os_regex/*.c zlib-1.2.3/*.c os_zlib.c shared/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/shared/*.c addagent/*.c -Iheaders/ -I. -lwsock32 -lshlwapi
"C:\MinGW\bin\gcc.exe" -o setup-windows -Wall os_regex/*.c -DARGV0=\"setup-windows\" -DCLIENT -DWIN32 win_service.c shared/file_op.c shared/debug_op.c setup/setup-win.c setup/setup-shared.c -Iheaders/ -I. -lwsock32
"C:\MinGW\bin\gcc.exe" -o setup-syscheck -Wall os_regex/*.c os_xml/*.c setup/setup-syscheck.c setup/setup-shared.c -I. -Iheaders/
"C:\MinGW\bin\gcc.exe" -o service-start -Wall icon.o os_regex/*.c setup/service-start.c -I.
"C:\MinGW\bin\gcc.exe" -o service-stop -Wall os_regex/*.c setup/service-stop.c -I.
"C:\MinGW\bin\gcc.exe" -o setup-iis -Wall os_regex/*.c setup/setup-iis.c -I.
"C:\MinGW\bin\gcc.exe" -o add-localfile -Wall os_regex/*.c setup/add-localfile.c -I.
cd ui\
make
