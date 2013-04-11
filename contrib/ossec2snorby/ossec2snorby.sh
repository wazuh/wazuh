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

[ -x /usr/local/bin/ossec2snorby/ossec2snorby.pl ] || { echo " [ERROR]: ossec2snorby.pl non existant or not executable..."; exit 1; }
[ -r /etc/ossec2snorby.conf ] || { echo " [ERROR]: ossec2snorby.conf was not found..."; exit 1; }
[ -r /usr/local/bin/ossec2snorby/ossecmysql.pm ] || { echo " [ERROR]: ossecmysql was not found..."; exit 1; }

### Default variables
SYSCONFIG="/etc/ossec2snorby.conf"

### Read configuration
[ -r "$SYSCONFIG" ] && . "$SYSCONFIG"

RETVAL=0
prog="ossec2snorby.pl"
homedir="/usr/local/bin/ossec2snorby"
desc="Ossec Output Processor"

start() {
        echo -n $"Starting $desc ($prog): "

        PIDFILE="/var/run/ossec2snorby.pid"
        OPTS="--conf $SYSCONFIG -d"
        $homedir/$prog $OPTS

        RETVAL=$?
        echo
        [ $RETVAL -eq 0 ] && touch /var/lock/$prog
        return $RETVAL
}

stop() {
        echo -n $"Shutting down $desc ($prog): "
        kill -n 3 $homedir/$prog
        RETVAL=$?
        echo
        [ $RETVAL -eq 0 ] && rm -f /var/lock/$prog
        return $RETVAL
}

restart() {
        stop
        start
}

case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  restart)
        restart
        ;;
  condrestart)
        [ -e /var/lock/$prog ] && restart
        RETVAL=$?
        ;;
  status)
        status $prog
        RETVAL=$?
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=1
esac

exit $RETVAL
