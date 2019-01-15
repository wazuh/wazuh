# Makefile for integratord
# Copyright (C) 2015-2019, Wazuh Inc.
# Daniel B. Cid <dcid@sucuri.net>

PT=../
NAME=ossec-integratord


include ../Config.Make
LOCAL = *.c


OBJS = ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML}

default:
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
