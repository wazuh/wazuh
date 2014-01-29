# Makefile for analysisd
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>
# http://www.ossec.net/hids/

PT=../
NAME=ossec-analysisd

include ../Config.Make

OTHER   = stats.c lists.c lists_list.c rules.c rules_list.c config.c fts.c dodiff.c eventinfo.c eventinfo_list.c cleanevent.c active-response.c picviz.c prelude.c zeromq_output.c compiled_rules/*.o ${OS_CONFIG}
LOCAL   = analysisd.c ${OTHER}
PLUGINS = decoders/decoders.a
ALERTS  = alerts/alerts.a
DBS     = cdb/cdb.a cdb/cdb_make.a

loga_OBJS = ${LOCAL} ${PLUGINS} ${DBS} ${ALERTS} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_SHARED} ${OS_ZLIB} ${CPRELUDE} ${OS_CJSON} ${CZEROMQ_OUTPUT}
lists_OBJS = lists_make.c ${OTHER} ${PLUGINS} ${DBS} ${ALERTS} ${OS_XML} ${OS_REGEX} ${OS_NET} ${OS_SHARED} ${OS_ZLIB} ${CPRELUDE} ${OS_CJSON} ${CZEROMQ_OUTPUT}

all: logaudit logtest makelists

logaudit:
	    cd ./cdb; make
		cd ./alerts; make
		cd ./decoders; make
		cd ./compiled_rules; make;
		$(CC) $(CFLAGS) ${OS_LINK} -I./ ${loga_OBJS} -o ${NAME}

logtest:
	    cd ./cdb; make
		cd ./decoders; make logtest
		cd ./compiled_rules; make;
		$(CC) $(CFLAGS) ${OS_LINK} -DTESTRULE -I./ testrule.c ${loga_OBJS} -o ossec-logtest

makelists:
		cd ./cdb; make
		$(CC) $(CFLAGS) ${OS_LINK} -DTESTRULE -I./ makelists.c ${lists_OBJS}  -o ossec-makelists

clean:
	    cd ./cdb; make clean
		cd ./alerts; make clean
		cd ./decoders; make clean
		cd ./compiled_rules; make clean
		${CLEAN} ossec-logtest ossec-makelists

build:
		${BUILD}
		cp -pr ossec-logtest ${PT}../bin
		cp -pr ossec-makelists ${PT}../bin
