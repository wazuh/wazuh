# Makefile for os_crypto md5
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/c/os_crypto/

PT=../../
NAME=md5_op

include ../../Config.Make

SRCS = md5.c md5_op.c
md5_OBJS = md5_op.o md5.o


md5:
		$(CC) $(CFLAGS) -c $(SRCS)
		ar cru md5_op.a $(md5_OBJS)
		ranlib md5_op.a
main:
		$(CC) $(CFLAGS) -o main main.c md5_op.a

clean:
		rm -f *.o *.a main
