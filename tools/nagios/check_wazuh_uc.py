#!/usr/bin/env python3

import sys
import sqlite3
import argparse

argp = argparse.ArgumentParser()
argp.add_argument('--level', help='severity level', type=int)
arg = argp.parse_args()
db_dir = '/var/ossec/var/db/integrations/'
db_file = 'alerts.db'
db_name = (db_dir + db_file)
threshold = 15
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

def set_sql():
    if arg.level:
        threshold = arg.level
        sql = 'SELECT COUNT(*) from alert WHERE\
         alert_level >= {} AND classification IS\
         NULL'.format(threshold)
    else:
        sql = 'SELECT COUNT(*) from alert WHERE\
         classification IS NULL'
    return sql

def check_alert_db():
    sql = set_sql()
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute(sql)
    result = cur.fetchone()
    conn.close()
    result_tuple = result
    return result_tuple

def get_alert_count():
    alerts = check_alert_db()
    alerts_count = (alerts[0])
    return alerts_count

def print_alert(exitcode=UNKNOWN, exitmsg='UNKNOWN - Status is unknown'):
    print (exitmsg)
    sys.exit(exitcode)

def main():
    cur_alerts = get_alert_count()
    if cur_alerts == 0:
        print_alert(exitcode=OK, exitmsg='OK - {} unclassified alerts'.format(cur_alerts))
    elif cur_alerts >= 1:
        print_alert(exitcode=CRITICAL, exitmsg='CRITICAL - There are {} unclassified alerts'.format(cur_alerts))
    else:
        print_alert()


if __name__ == "__main__":
    main()
