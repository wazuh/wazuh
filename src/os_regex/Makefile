# Makefile for os_regex
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/c/os_regex/

PT=../
NAME=os_regex

include ../Config.Make

SRCS =  os_regex.c os_regex_match.c os_regex_strbreak.c 
OBJS =  os_regex_match.o os_regex.o os_regex_strbreak.o 

regex:
		$(CC) $(CFLAGS) -c $(SRCS) -Wall
		ar cru os_regex.a ${OBJS}
		ranlib os_regex.a

main:
		$(CC) $(CFLAGS) -o main main.c os_regex.a

clean:
		${CLEAN}
		rm -f main
