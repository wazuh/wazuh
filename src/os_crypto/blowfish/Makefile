# Makefile for os_crypto blowfish
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/c/os_crypto/

PT=../../

NAME=blowfish_op

include ../../Config.Make

SRCS = bf_op.c bf_skey.c bf_enc.c

bf_OBJS = bf_op.o bf_skey.o bf_enc.o


bf:
		$(CC) $(CFLAGS) -c $(SRCS)
		ar cru bf_op.a $(bf_OBJS)
		ranlib bf_op.a

main:
		$(CC) $(CFLAGS) -o main main.c bf_op.a

clean:
		rm -f *.o *.a 
