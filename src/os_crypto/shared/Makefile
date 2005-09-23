# Makefile for os_crypto shared
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/c/os_crypto/

PT=../../
NAME=shared

include ../../Config.Make

SRCS = sec.c
OBJS = sec.o


shared:
		$(CC) $(CFLAGS) -c $(SRCS)
		ar cru shared.a $(OBJS)
		ranlib shared.a
clean:
		${CLEAN}
