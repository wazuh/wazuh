# Makefile for remoted
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-remoted

include ../Config.Make

LOCAL = remoted.c config.c manager.c ar-forward.c

rlog_OBJS = ${LOCAL} ${OS_SHARED} ${OS_NET} ${OS_XML} ${OS_REGEX} ${OS_CRYPTO} ${TEXTRA}

remoted:
		${CC} ${CFLAGS}  ${rlog_OBJS} -o ${NAME}

clean:
		${CLEAN}
build:
		${BUILD}
