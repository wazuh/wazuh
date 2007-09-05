# Makefile for os_regex
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=os_regex

include ../Config.Make

SRCS =  *.c
OBJS =  *.o

regex:
		$(CC) $(CFLAGS) -c $(SRCS) -Wall
		ar cru os_regex.a ${OBJS}
		ranlib os_regex.a

main:
		$(CC) $(CFLAGS) -o main main.c os_regex.a

clean:
		${CLEAN}
		rm -f main
