echo Making windows agent

"C:\MinGW\bin\gcc.exe" -o "ossec-agent" -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 os_regex/*.c os_net/*.c os_xml/*.c config/*.c shared/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/shared/*.c *.c -Iheaders/ -I./ -lwsock32
"C:\MinGW\bin\gcc.exe" -o "manage_agents" -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 os_regex/*.c shared/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/shared/*.c addagent/*.c win_service.c -Iheaders/ -I./ -lwsock32
