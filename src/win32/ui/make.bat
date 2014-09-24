echo Making windows agent UI

"C:\MinGW\bin\windres.exe" -o resource.o win32ui.rc
"C:\MinGW\bin\gcc.exe" -o "os_win32ui" -Wall -DARGV0=\"ossec-win32ui\" -DCLIENT -DWIN32 resource.o ../os_net/*.c ../os_xml/*.c ../addagent/b64.c ../shared/validate_op.c ../shared/debug_op.c ../shared/file_op.c ../win_service.c *.c -I../headers/ -I../ -lcomctl32 -mwindows -lwsock32 -lws2_32
copy os_win32ui.exe ..\
cd ../
