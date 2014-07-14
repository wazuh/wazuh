# Makefile for os_crypto sha1
# Daniel B. Cid <dcid@ossec.net>


PT=../../
NAME=sha1_op

include ../../Config.Make

SRCS = sha1_op.c
sha1_OBJS = sha1_op.o

sha1_op.a: ${SRCS} *.h
		${CC} ${CFLAGS} -c ${SRCS}
		${BUILDLIB} sha1_op.a $(sha1_OBJS)

main: main.c sha1_op.a
		${CC} ${CFLAGS} -o main main.c sha1_op.a

clean:
		${CLEAN} main
