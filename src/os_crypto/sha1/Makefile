# Makefile for os_crypto sha1
# Daniel B. Cid <dcid@ossec.net>


PT=../../
NAME=sha1_op

include ../../Config.Make

SRCS = sha1_op.c
sha1_OBJS = sha1_op.o

sha1:
		$(CC) $(CFLAGS) -c $(SRCS)
		ar cru sha1_op.a $(sha1_OBJS)
		ranlib sha1_op.a
main:
		$(CC) $(CFLAGS) -o main main.c sha1_op.a

clean:
		rm -f *.o *.a main
