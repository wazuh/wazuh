# Makefile for analysisd
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-analysisd

include ../Config.Make

LOCAL= analysisd.c stats.c rules.c rules_list.c config.c fts.c eventinfo.c eventinfo_list.c cleanevent.c active-response.c prelude.c compiled_rules/*.o ${OS_CONFIG}
PLUGINS = decoders/decoders.a
ALERTS  = alerts/alerts.a

loga_OBJS = ${LOCAL} ${PLUGINS} ${ALERTS} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_SHARED} ${OS_ZLIB} ${CPRELUDE}


logaudit:
		cd ./alerts; make
		cd ./decoders; make
		cd ./compiled_rules; make;
		$(CC) $(CFLAGS) ${OS_LINK} -I./ ${loga_OBJS} -o ${NAME}

logtest:
		cd ./alerts; make
		cd ./decoders; make logtest
		cd ./compiled_rules; make;
		$(CC) $(CFLAGS) ${OS_LINK} -DTESTRULE -I./ testrule.c ${loga_OBJS} -o ossec-logtest 

clean:
		cd ./alerts; make clean
		cd ./decoders; make clean
		cd ./compiled_rules; make clean
		${CLEAN}

build:
		${BUILD}
