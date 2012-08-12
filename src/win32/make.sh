echo Making windows agent

i686-pc-mingw32-windres -i icofile.rc -o icon.o
i686-pc-mingw32-gcc -o ossec-agent.exe -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 -DOSSECHIDS icon.o os_regex/*.c os_net/*.c os_xml/*.c zlib-1.2.3/*.c config/*.c shared/*.c os_execd/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/sha1/*.c os_crypto/md5_sha1/*.c os_crypto/shared/*.c rootcheck/*.c *.c -Iheaders/ -I./ -lwsock32
i686-pc-mingw32-gcc -o ossec-rootcheck.exe -Wall  -DARGV0=\"ossec-rootcheck\" -DCLIENT -DWIN32 icon.o os_regex/*.c os_net/*.c os_xml/*.c config/*.c shared/*.c win_service.c rootcheck/*.c -Iheaders/ -I./ -lwsock32
i686-pc-mingw32-gcc -o manage_agents.exe -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 -DMA os_regex/*.c zlib-1.2.3/*.c os_zlib.c shared/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/shared/*.c addagent/*.c -Iheaders/ -I./ -lwsock32
i686-pc-mingw32-gcc -o agent-auth.exe -Wall  -DARGV0=\"agent-auth\" -DUSE_OPENSSL -DCLIENT -DWIN32 -DMA os_auth/main-client.c os_auth/ssl.c  addagent/validate.c os_net/*.c os_regex/*.c zlib-1.2.3/*.c os_zlib.c shared/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/shared/*.c  -Iheaders/ -I./ -lwsock32 -lssl -lcrypto
i686-pc-mingw32-gcc -o setup-windows.exe -Wall os_regex/*.c -DARGV0=\"setup-windows\" -DCLIENT -DWIN32 win_service.c shared/file_op.c shared/debug_op.c setup/setup-win.c setup/setup-shared.c -Iheaders/ -I./ -lwsock32
i686-pc-mingw32-gcc -o setup-syscheck.exe -Wall os_regex/*.c os_xml/*.c setup/setup-syscheck.c setup/setup-shared.c -I./ -Iheaders/
i686-pc-mingw32-gcc -o service-start.exe -Wall icon.o os_regex/*.c setup/service-start.c -I./
i686-pc-mingw32-gcc -o service-stop.exe -Wall os_regex/*.c setup/service-stop.c -I./
i686-pc-mingw32-gcc -o setup-iis.exe -Wall os_regex/*.c setup/setup-iis.c -I./
i686-pc-mingw32-gcc -o add-localfile.exe -Wall os_regex/*.c setup/add-localfile.c -I./

cd ui
sh ./make.sh
cd ../

makensis ui.nsi
makensis ossec-installer.nsi
