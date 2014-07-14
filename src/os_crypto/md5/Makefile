# Makefile for os_crypto md5
# Daniel B. Cid <dcid@sourcefire.com>||<daniel@underlinux.com.br>

PT=../../
NAME=md5_op

include ../../Config.Make

SRCS = md5.c md5_op.c
md5_OBJS = md5_op.o md5.o


md5_op.a: ${SRCS} *.h
		${CC} ${CFLAGS} -c ${SRCS}
		${BUILDLIB} md5_op.a ${md5_OBJS}

main: main.c md5_op.a
		${CC} ${CFLAGS} -o main main.c md5_op.a

clean:
		${CLEAN} main
