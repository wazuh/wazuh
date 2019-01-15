#!/bin/sh

# Copyright (C) 2015-2019, Wazuh Inc.

MI=""
ML=""
PI=""
PL=""

# Look for MySQL
ls "`which mysql 2>/dev/null`" > /dev/null 2>&1
if [ $? = 0 ]; then
    # Check if mysql_config is installed to use it
    mysql_config --port > /dev/null 2>&1
    if [ $? = 0 ]; then
        MI=`mysql_config --cflags`
        ML=`mysql_config --libs`
    fi

    # Check in a few dirs if mysql_config is perhaps there
    for i in /usr /usr/local $1
    do
    for j in $i/include/mysql/mysql.h $i/include/mysql.h
        do
            ls $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                if [ "X$MI" = "X" ]; then
                    MI="-I `dirname $j`";
                fi
                break;
            fi
        done

    for j in $i/lib/mysql $i/lib64/mysql
        do
            ls $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                if [ "X$ML" = "X" ]; then
                    ML="-L $j -lmysqlclient";
                fi
                break
            fi
        done
    done
fi

# Look for PostgreSQL
ls "`which psql 2>/dev/null`" > /dev/null 2>&1
if [ $? = 0 ]; then
    # Check if pg_config is installed to use it
    pg_config --version > /dev/null 2>&1
    if [ $? = 0 ]; then
        PGID=`pg_config --includedir`
        PGPI=`pg_config --pkgincludedir`
        PGLD=`pg_config --libdir`
        PGLI=`pg_config --pkglibdir`
        PI="${PGID} -I${PGPI}"
        PL="-L${PGLD} -L${PGLI}"
    fi

    for i in /usr /usr/local /usr/local/pgsql /usr/pgsql /usr/postgresql $1
    do
    for j in $i/include/pgsql/libpq-fe.h $i/include/libpq-fe.h $i/include/postgresql/libpq-fe.h
        do
            ls $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                if [ "X$PI" = "X" ]; then
                    PI=`dirname $j`;
                fi
                break;
            fi
        done

    for j in $i/lib/pgsql $i/lib/postgresql $i/lib64/pgsql $i/lib64/postgresql
        do
            ls $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                if [ "X$PL" = "X" ]; then
                    PG_MAIN=`dirname $j`;
                    PL="-L$j -L${PG_MAIN}";
                fi
                break
            fi
        done
    done
fi

# Print error if MySQL is not found
if [ "X$MI" = "X" -a "X$ML" = "X" ]; then
    echo "" >&2
    echo "Error: MySQL client libraries not installed." >&2
    echo "" >&2
fi

# Print error if PostgreSQL is not found
if [ "X$PI" = "X" -a "X$PL" = "X" ]; then
    echo "" >&2
    echo "Error: PostgreSQL client libraries not installed." >&2
    echo "" >&2
fi

# Final MySQL CFLAGS
if [ "X$MI" = "X" -o "X$ML" = "X" ]; then
    MYSQL_FINAL=""
else
    echo "Info: Compiled with MySQL support." >&2
    MYSQL_FINAL="$MI $ML -DDBD -DUMYSQL"
fi

# Final PostgreSQL CFLAGS
if [ "X$PI" = "X" -o "X$PL" = "X" ]; then
    POSTGRES_FINAL=""
else
    echo "Info: Compiled with PostgreSQL support." >&2
    POSTGRES_FINAL="-I$PI $PL -lpq -DDBD -DUPOSTGRES"
fi


if [ "X${MYSQL_FINAL}" = "X" -a "X${POSTGRES_FINAL}" = "X" ]; then
    echo "Error: DB libraries not installed." >&2
    exit 1;
fi

echo "${MYSQL_FINAL} ${POSTGRES_FINAL}"

exit 0;

