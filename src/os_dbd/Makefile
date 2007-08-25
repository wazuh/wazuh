# Makefile for dbd
# Daniel B. Cid <dcid@ossec.net>

PT=../
NAME=ossec-dbd

# Uncomment the following if you know what you are doing.
#DBFLAGS=-I/usr/local/include/mysql -L/usr/local/lib/mysql -lmysqlclient

include ../Config.Make

LOCAL = *.c


# Getting database cflags
DBCHECK = `./dbmake.sh`
DBMYSQL = `./dbmake.sh mysql 2> /dev/null`
DBPOSTGRES =  `./dbmake.sh postgresql 2> /dev/null` 


OBJS = ${OS_CONFIG} ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML}

default:
		@echo "Compiling DB support with: ${DBCHECK}"
		${CC} ${CFLAGS} ${DBFLAGS} ${DBCHECK} ${LOCAL} ${OBJS} -o ${NAME}
mysql:
		@if [ "X${DBMYSQL}" = "X" ]; then ./dbmake.sh mysql; exit 1; fi;
		@echo "Compiling MySQL DB support with: ${DBMYSQL}"
		${CC} ${CFLAGS} ${DBFLAGS} ${DBMYSQL} ${LOCAL} ${OBJS} -o ${NAME}
postgresql:
		@if [ "X${DBPOSTGRES}" = "X" ]; then ./dbmake.sh postgresql; exit 1; fi;
		@echo "Compiling PostgreSQL DB support with: ${DBPOSTGRES}"
		${CC} ${CFLAGS} ${DBFLAGS} ${DBPOSTGRES} ${LOCAL} ${OBJS} -o ${NAME}
clean:
		${CLEAN}
build:
		${BUILD}
