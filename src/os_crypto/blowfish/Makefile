# Makefile for os_crypto blowfish
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>

PT=../../

NAME=blowfish_op

include ../../Config.Make

SRCS = bf_op.c bf_skey.c bf_enc.c

bf_OBJS = bf_op.o bf_skey.o bf_enc.o


bf_op.a: ${SRCS} *.h
		${CC} ${CFLAGS} -c ${SRCS}
		${BUILDLIB} bf_op.a ${bf_OBJS}

main: main.c bf_op.a
		${CC} ${CFLAGS} -o main main.c bf_op.a

clean:
		${CLEAN} main
