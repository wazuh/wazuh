#!/bin/sh

# exit on error
set -e

echo Making windows agent UI

${MING_BASE}-windres -o resource.o win32ui.rc
${MING_BASE}-gcc -o os_win32ui.exe -Wall -DARGV0=\"ossec-win32ui\" -DCLIENT -DWIN32 resource.o ../os_net/*.c ../os_xml/*.c ../addagent/b64.c ../shared/validate_op.c ../shared/debug_op.c ../win_service.c *.c -I../headers/ -I../ -lcomctl32 -mwindows -lwsock32
cp -pr  os_win32ui.exe ../
cd ../
