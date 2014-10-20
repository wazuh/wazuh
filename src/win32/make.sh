#!/bin/sh

echo "Making windows agent"
BASES="amd64-mingw32msvc i686-pc-mingw32  i686-w64-mingw32"

if [ ${MING_BASE} ]; then
  BASES="${BASES} ${MING_BASE}"
fi

for i in ${BASES}; do
  which ${i}-gcc > /dev/null 2>&1
  if [ "$?" = "0" ]; then
    export MING_BASE=${i}
  fi
done

if [ ! ${MING_BASE} ]; then
  echo "Could not find suitable base from (${BASES})"
  exit 1
fi

echo "Using ${MING_BASE} as base"

# exit on error
set -e

echo ""
echo "*** Making resource files ***"
echo ""
${MING_BASE}-windres -i icofile.rc -o icon.o

echo ""
echo "*** Making agent ***"
echo ""
${MING_BASE}-gcc -o ossec-agent.exe -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 -DOSSECHIDS icon.o os_regex/*.c os_net/*.c os_xml/*.c zlib-1.2.8/*.c config/*.c shared/*.c os_execd/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/sha1/*.c os_crypto/md5_sha1/*.c os_crypto/shared/*.c rootcheck/*.c *.c -Iheaders/ -I./ -lwsock32 -lshlwapi -lws2_32

echo ""
echo "*** Making agent with event channel ***"
echo ""
${MING_BASE}-gcc -o ossec-agent-eventchannel.exe -Wall  -DARGV0=\"ossec-agent\" -DCLIENT -DWIN32 -DOSSECHIDS -DEVENTCHANNEL_SUPPORT icon.o os_regex/*.c os_net/*.c os_xml/*.c zlib-1.2.8/*.c config/*.c shared/*.c os_execd/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/sha1/*.c os_crypto/md5_sha1/*.c os_crypto/shared/*.c rootcheck/*.c *.c -Iheaders/ -I./ -lwsock32 -lshlwapi -lwevtapi -lws2_32

echo ""
echo "*** Making rootcheck ***"
echo ""
${MING_BASE}-gcc -o ossec-rootcheck.exe -Wall  -DARGV0=\"ossec-rootcheck\" -DCLIENT -DWIN32 icon.o os_regex/*.c os_net/*.c os_xml/*.c config/*.c shared/*.c win_service.c rootcheck/*.c -Iheaders/ -I./ -lwsock32 -lshlwapi -lws2_32

echo ""
echo "*** Making manage agents***"
echo ""
${MING_BASE}-gcc -o manage_agents.exe -Wall  -DARGV0=\"manage-agents\" -DCLIENT -DWIN32 -DMA os_regex/*.c zlib-1.2.8/*.c os_zlib.c shared/*.c os_crypto/blowfish/*.c os_crypto/md5/*.c os_crypto/shared/*.c addagent/*.c -Iheaders/ -I./ -lwsock32 -lshlwapi -lws2_32

echo ""
echo "*** Making setup Windows ***"
echo ""
${MING_BASE}-gcc -o setup-windows.exe -Wall os_regex/*.c -DARGV0=\"setup-windows\" -DCLIENT -DWIN32 win_service.c shared/file_op.c shared/debug_op.c setup/setup-win.c setup/setup-shared.c -Iheaders/ -I./ -lwsock32 -lshlwapi -lws2_32

echo ""
echo "*** Making setup syscheck ***"
echo ""
${MING_BASE}-gcc -o setup-syscheck.exe -Wall os_regex/*.c os_xml/*.c setup/setup-syscheck.c setup/setup-shared.c -I./ -Iheaders/

echo ""
echo "*** Making setup IIS ***"
echo ""
${MING_BASE}-gcc -o setup-iis.exe -Wall os_regex/*.c setup/setup-iis.c -I./

echo ""
echo "*** Making add local file ***"
echo ""
${MING_BASE}-gcc -o add-localfile.exe -Wall os_regex/*.c setup/add-localfile.c -I./

cd lua
echo ""
echo "*** Making LUA ***"
echo ""
make -f Makefile.mingw mingw
cd ../
cp lua/ossec-lua.exe ossec-lua.exe
cp lua/ossec-luac.exe ossec-luac.exe

cd ui
sh ./make.sh
cd ../


makensis ossec-installer.nsi
