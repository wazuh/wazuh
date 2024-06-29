#!/usr/bin/env python3

import sys
import sqlite3
import argparse

argp = argparse.ArgumentParser()
argp.add_argument('--level', help='severity level (default 15)', type=int, default=15)
argp.add_argument('--db_dir', help='database directory', type=str, default='/var/ossec/var/db/integrations/')
argp.add_argument('--db_file', help='sqlite database file', type=str, default='alerts.db')
argp.add_argument('--show_hosts', help='show a count for each host', action='store_true')
arg = argp.parse_args()
threshold = arg.level
show_hosts = arg.show_hosts
db_dir = arg.db_dir
db_file = arg.db_file
db_name = (db_dir + db_file)

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

def host_sql():
    sql = 'SELECT agent_name,COUNT(*) from alert\
       WHERE alert_level >= {} AND classification IS\
       NULL GROUP by agent_name'.format(threshold)
    return sql

def alert_sql():
    sql = 'SELECT COUNT(*) from alert WHERE\
      alert_level >= {} AND classification IS\
      NULL'.format(threshold)
    return sql

def check_alert_db(sql_query, fetch):
    sql = sql_query
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute(sql)
    if fetch == 'one':
        result = cur.fetchone()
    if fetch == 'all':
        result = cur.fetchall()
    conn.close()
    result_tuple = result
    return result_tuple

def get_alert_count():
    fetch = 'one'
    alerts = check_alert_db(alert_sql(), fetch)
    alerts_count = (alerts[0])
    return alerts_count

def get_alerts_by_host():
    fetch = 'all'
    alerts = check_alert_db(host_sql(), fetch)
    host_alerts = (alerts)
    return host_alerts

def print_alert(exitcode=UNKNOWN, exitmsg='UNKNOWN - Status is unknown'):
    print (exitmsg)
    sys.exit(exitcode)

def main():
    cur_alerts = get_alert_count()
    if cur_alerts == 0:
        print_alert(exitcode=OK, exitmsg='OK - {} unclassified alerts'.format(cur_alerts))
    elif cur_alerts >= 1:
        if show_hosts:
            host_alerts = get_alerts_by_host()
            print_alert(exitcode=CRITICAL, exitmsg='CRITICAL - There are {} unclassified alerts on: {}'.format(cur_alerts, host_alerts))
        else:
            print_alert(exitcode=CRITICAL, exitmsg='CRITICAL - There are {} unclassified alerts'.format(cur_alerts))
    else:
        print_alert()


if __name__ == "__main__":
    main()
