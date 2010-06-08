# Makefile for analysisd alerts
# Daniel B. Cid <dcid@sourcefire.com>||<daniel.cid@gmail.com>
# http://www.ossec.net/hids/

PT=../../
NAME=cdb

include ../../Config.Make

SRCS = cdb.c cdb_hash.c cdb_make.c uint32_pack.c uint32_unpack.c
OBJS = cdb.o cdb_hash.o cdb_make.o uint32_pack.o uint32_unpack.o


response:
		$(CC) -I../ $(CFLAGS) -c $(SRCS)
		ar cru cdb.a $(OBJS)
		ar cru cdb_make.a $(OBJS)
		ranlib cdb.a
		ranlib cdb_make.a

clean:
		${CLEAN}
