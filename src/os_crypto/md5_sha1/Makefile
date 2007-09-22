# Makefile for os_crypto md5_sha1
# Daniel B. Cid <dcid@ossec.net>

PT=../../
NAME=md5_sha1_op

include ../../Config.Make

SRCS = ../md5/md5.c md5_sha1_op.c
md5_OBJS = md5_sha1_op.o ../md5/md5.o


md5:
		$(CC) $(CFLAGS) -c $(SRCS)
		ar cru md5_op.a $(md5_OBJS)
		ranlib md5_op.a
main:
		$(CC) $(CFLAGS) -o main main.c md5_op.a

clean:
		rm -f *.o *.a main
