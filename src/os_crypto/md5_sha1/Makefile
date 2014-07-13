# Makefile for os_crypto md5_sha1
# Daniel B. Cid <dcid@ossec.net>

PT=../../
NAME=md5_sha1_op

include ../../Config.Make

SRCS = ../md5/md5.c md5_sha1_op.c
md5_OBJS = md5_sha1_op.o ../md5/md5.o


md5_sha1_op.a: ${SRCS} *.h
		${CC} ${CFLAGS} -c ${SRCS}
		${BUILDLIB} md5_sha1_op.a $(md5_OBJS)

main: main.c md5_sha1_op.a
		${CC} ${CFLAGS} -o main main.c md5_op.a

clean:
		${CLEAN} main
