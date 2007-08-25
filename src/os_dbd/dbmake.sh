#!/bin/sh


MI=""
ML=""
PI=""
PL=""


# Looking for mysql
ls "`which mysql`" > /dev/null 2>&1
if [ $? = 0 ]; then
    for i in /usr /usr/local $1
    do    
    for j in $i/include/mysql/mysql.h $i/include/mysql.h
        do
            ls $j > /dev/null 2>&1 
            if [ $? = 0 ]; then
                MI=`dirname $j`;
                break;
            fi
        done
    
    for j in $i/lib/mysql
        do
            ls $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                ML="$j -lmysqlclient";
                break
            fi    
        done
    done               
fi


# Looking for postgresql
ls "`which psql`" > /dev/null 2>&1
if [ $? = 0 ]; then
    for i in /usr /usr/local /usr/pgsql /usr/postgresql $1
    do    
    for j in $i/include/pgsql/libpq-fe.h $i/include/libpq-fe.h $i/include/postgresql/libpq-fe.h
        do
            ls $j > /dev/null 2>&1 
            if [ $? = 0 ]; then
                PI=`dirname $j`;
                break;
            fi
        done
    
    for j in $i/lib/pgsql $i/lib/postgresql
        do
            ls $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                PL="$j -lpq";
                break
            fi    
        done
    done               
fi




# Printing error if mysql is not found
if [ "X$1" = "Xmysql" -a "X$MI" = "X" -a "X$ML" = "X" ]; then
    echo "" >&2
    echo "Error: MySQL client libraries not installed." >&2
    echo "" >&2
    exit 1; 
fi

# Printing error if postgresql is not found
if [ "X$1" = "Xpostgresql" -a "X$PI" = "X" -a "X$PL" = "X" ]; then
    echo "" >&2
    echo "Error: PostgreSQL client libraries not installed." >&2
    echo "" >&2
    exit 1; 
fi


# Final cflags -- can not be empty.
if [ "X$MI" = "X" -o "X$ML" = "X" ]; then
    MYSQL_FINAL=""
else
    MYSQL_FINAL="-I$MI -L$ML -DDBD -DUMYSQL"    
fi

# For postgresql
if [ "X$PI" = "X" -o "X$PL" = "X" ]; then
    POSTGRES_FINAL=""
else
    POSTGRES_FINAL="-I$PI -L$PL -DDBD -DUPOSTGRES"    
fi


echo "${MYSQL_FINAL} ${POSTGRES_FINAL}"

exit 0;

