# Makefile for maild
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=ossec-maild

include ../Config.Make

LOCAL = maild.c config.c os_maild_client.c sendmail.c mail_list.c

OBJS = ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML}

addclient:
		${CC} ${CFLAGS} ${LOCAL} ${OBJS} -o ${NAME}
		${CC} ${CFLAGS} -c ${LOCAL}
clean:
		${CLEAN}
build:
		${BUILD}
