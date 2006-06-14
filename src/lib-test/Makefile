# Makefile for library tests.
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net
PT=../
include $(PT)Config.Make

OBJS = ${OS_SHARED} ${OS_ZLIB}

me:
		$(CC) $(CFLAGS) zlib-test.c $(OBJS) -o zlib-test
clean:
		$(CLEAN) zlib-test
