#!/usr/bin/env python3

import sys
import sqlite3

db_dir = '/var/ossec/var/db/integrations/'
db_file = 'alerts.db'
db_name = (db_dir + db_file)
alert_level = 15
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3


def check_alert_db():
    level = (alert_level,)
    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) \
      from alert WHERE alert_level >= ? \
      AND classification IS NULL', level)
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
        print_alert(exitcode=OK, exitmsg='OK')
    elif cur_alerts >= 1:
        print_alert(exitcode=CRITICAL, exitmsg='CRITICAL - There are unclassified alerts')
    else:
        print_alert()


if __name__ == "__main__":
    main()
