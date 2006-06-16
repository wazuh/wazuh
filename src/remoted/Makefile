# Makefile for remoted
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-remoted

include ../Config.Make

rlog_OBJS = *.c ${OS_CONFIG} ${OS_ZLIB} ${OS_SHARED} ${OS_NET} ${OS_XML} ${OS_REGEX} ${OS_CRYPTO} ${TEXTRA}

remoted:
		${CC} ${CFLAGS}  ${rlog_OBJS} -o ${NAME}

clean:
		${CLEAN}
build:
		${BUILD}
