# Makefile for analysisd alerts
# Daniel B. Cid <dcid@sourcefire.com>||<daniel.cid@gmail.com>
# http://www.ossec.net/hids/

PT=../../
NAME=alerts

include ../../Config.Make

SRCS = mail.c log.c exec.c getloglocation.c
OBJS = mail.o log.o exec.o getloglocation.o


response:
		$(CC) -I../ $(CFLAGS) -c $(SRCS)
		ar cru alerts.a $(OBJS)
		ranlib alerts.a

clean:
		${CLEAN}
