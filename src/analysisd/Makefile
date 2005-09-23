# Makefile for analysisd
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-analysisd

include ../Config.Make

LOCAL= analysisd.c stats.c rules.c rules_list.c config.c fts.c eventinfo.c eventinfo_list.c cleanevent.c
PLUGINS = decoders/decoders.a ../shared/mem_op.o
ALERTS  = alerts/alerts.a ../os_maild/os_maild_client.o ../os_execd/os_execd_client.o

loga_OBJS = ${LOCAL} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_SHARED} ${PLUGINS} ${ALERTS}


logaudit:
		cd ./alerts; make
		cd ./decoders; make
		$(CC) $(CFLAGS) -I./ ${loga_OBJS} -o ${NAME}

clean:
		cd ./alerts; make clean
		cd ./decoders; make clean
		${CLEAN}

build:
		${BUILD}
