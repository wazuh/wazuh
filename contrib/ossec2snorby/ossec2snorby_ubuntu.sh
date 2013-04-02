#!/bin/sh
#
# Init file for ossec2snorby.pl
#
#
# chkconfig: 2345 40 60
# description:  ossec2snorby is an output processor for ossec.
#
# processname: ossec2snorby
# config: /etc/ossec2snorby.conf
# pidfile: /var/run/ossec2snorby.pid

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/local/bin/ossec2snorby/ossec2snorby.pl
PERLPATH=`which perl` || { echo "  [ERROR]:perl not found."; exit 1; }
NAME="ossec2snorby.pl"
DESC="Ossec2Snorby Output Processor"
PIDFILE="/var/run/ossec2snorby.pid"
CONFIGFILE="/etc/ossec2snorby.conf"
OPTS="--conf $CONFIGFILE -d"

[ -x $DAEMON ] || { echo " [ERROR]: ossec2snorby.pl non existant or not executable..."; exit 1; }
[ -r $CONFIGFILE ] || { echo " [ERROR]: ossec2snorby.conf was not found..."; exit 1; }
[ -r /usr/local/bin/ossec2snorby/ossecmysql.pm ] || { echo " [ERROR]: ossecmysql was not found..."; exit 1; }

set -e

case "$1" in
    start)
        echo -n "Starting $DESC: "
        start-stop-daemon --start --background --start --exec $DAEMON -- $OPTS
        echo "$NAME."
        ;;
    stop)
        echo -n "Stopping $DESC: "
        start-stop-daemon --stop --oknodo --quiet --pidfile $PIDFILE
        rm -f $PIDFILE
        echo "$NAME."
        ;;
    restart)
        echo -n "Restarting $DESC: "
        start-stop-daemon --stop --oknodo --quiet --pidfile $PIDFILE
        rm -f $PIDFILE
        sleep 2
        start-stop-daemon --start --background --start --exec $DAEMON -- $OPTS
        echo "$NAME."
        ;;
    status)  # NOT WORKING !!!
        status_of_proc -p "$PIDFILE" "$PERLPATH" "perl && exit 0 || exit $?
        ;;
    *)
        echo "Usage: $0 { start | restart | stop }" >&2
        exit 1
        ;;
esac

exit 0