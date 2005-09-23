# Makefile for os_net
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/c/os_net/

PT=../
NAME=os_net

include ../Config.Make

SRCS =  os_net.c
OBJS =  os_net.o

net:
		$(CC) $(CFLAGS) -c $(SRCS)
		ar cru os_net.a ${OBJS}
		ranlib os_net.a

clean:
		${CLEAN}
