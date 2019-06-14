#!/usr/bin/env python3

# User menu to ack alerts and clear them    #
# from apearing on your nagios monitoring.  #
# Alerts are inserted with the integrator   #
# plugin: integrations/custom-sqlite        #
# Nagios alerts are generated with plugin:  #
# nagios/check_wazuh_uc.py                  #

import sys
import sqlite3
from os import get_terminal_size

try:
    tty_size = int(get_terminal_size().columns)
except:
    tty_size = 79
    print ('Cannot detect tty column size, falling back to ' + str(tty_size))

try:
    import texttable as tt
    tab = tt.Texttable(max_width=tty_size)
    pretty_ascii = True
except Exception as e:
    print('Module "texttable" not found. Install it to get pretty ascii tables')
    pretty_ascii = False



# TODO: accept alternative db location/name
db_dir = '/var/ossec/var/db/integrations/'
db_file = 'alerts.db'
db_name = (db_dir + db_file)
sql_unc = 'SELECT * from alert WHERE classification IS NULL'
sql_all = 'SELECT * from alert'


def user_menu():

    """User menu options."""

    def print_menu():
        print(59 * ' ')
        print(20 * '-', 'SIEM SOC OPS MENU', 20 * '-')
        print('1. Display all unclassified alerts ')
        print('2. Display all alerts, ever ')
        print('3. Classify a single alert ')
        print('4. Classify a range of alerts ')
        print('5. Classify ALL unclassified alerts (careful now) ')
        print('6. Quit ')
        print(59 * '-')
        print(59 * ' ')

    while True:
        print_menu()
        while True:
            try:
                choice = int(input("Enter your choice [1-6]: "))

            except ValueError:
                print("Please enter a valid number.")

            else:
                if 1 <= choice <= 5:
                    break
                elif choice == 6:
                    print("Exiting..")
                    break
                else:
                    input("Invalid. Press any key..")
        return choice


def db_conn():
    # TODO: add a method to connect to the db
    pass


def display_unc():

    """Print unclassified alerts."""

    if pretty_ascii:
        tab.reset()

    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute(sql_unc)

    # Make the tuple a list, remove unnecessary indexes and
    # fiddle with the timestamp format before printing it out
    for row in cur:
        row = list(row[:-1])
        row.pop(1)
        d = row.pop(3).split('T', maxsplit=1)
        t = d.pop(1).split('.', maxsplit=1)
        t.pop(1)
        tstamp = d + t
        row.extend(tstamp)

        if pretty_ascii:
            tab.add_row(row)
        else:
            print ('ID: {0[0]:<3}- Level: {0[1]:<3}- Description: {0[2]:^} - Host: {0[3]:<5} - Date: {0[4]} - Time: {0[5]}'.format(row))

    if pretty_ascii:
        header = ['ID', 'Level', 'Description', 'Host', 'Date', 'Time']
        tab.header(header)
        final_table = tab.draw()
        print (final_table)

    conn.close()


def display_all():

    """Print every alert logged to the database."""

    if pretty_ascii:
        tab.reset()

    conn = sqlite3.connect(db_name)
    cur = conn.cursor()
    cur.execute(sql_all)

    # Make the tuple a list, and fiddle with the timestamp
    # format before printing it out
    for row in cur:
        row = list(row)
        row.pop(1)
        d = row.pop(3).split('T', maxsplit=1)
        t = d.pop(1).split('.', maxsplit=1)
        t.pop(1)
        tstamp = d + t
        row.extend(tstamp)

        if pretty_ascii:
            tab.add_row(row)
        else:
            print ('ID: {0[0]:<3}- Level: {0[1]:<3}- Description: {0[2]:^} - Host: {0[3]} - Classification: {0[4]} - Date: {0[5]} - Time: {0[6]}'.format(row))

    if pretty_ascii:
        header = ['ID', 'Level', 'Description', 'Host', 'Classification',\
            'Date', 'Time']
        tab.header(header)
        final_table = tab.draw()
        print (final_table)

    conn.close()


def gen_sql(class_txt, db_id):

    """Generate the sql statement used to classify alerts."""

    final_text = class_txt
    c_id = db_id
    sql_cls = 'UPDATE alert SET classification = "{}" WHERE id = "{}" AND classification IS NULL'.format(final_text, c_id)
    return sql_cls


def classify_alert():

    """Classify a single alert by ID from the list."""

    while True:
        c_name = input("Your name/initials? ")
        c_text = input("Enter classification text: ")

        try:
            c_id = int(input("Enter an ID value to classify: "))

        except ValueError:
            print("Please enter a valid number.")

        else:
            final_text = (c_name + ':' + ' ' + c_text)
            sql = gen_sql(final_text, c_id)
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()
            cur.execute(sql)
            conn.commit()
            conn.close()
            break


def classify_range():

    """Classify a range of alerts with a start and end ID."""

    while True:
        c_name = input("Your name/initials? ")
        c_text = input("Enter classification text: ")

        try:
            c_id_s = int(input("Enter a start range of IDs to update: "))
            c_id_e = int(input("Enter a end range of IDs to update: "))

        except ValueError:
            print("Please enter a valid number.")

        else:
            final_text = (c_name + ':' + ' ' + c_text)
            conn = sqlite3.connect(db_name)
            cur = conn.cursor()

            for c_id in range(c_id_s, c_id_e + 1):
                sql = gen_sql(final_text, c_id)
                cur.execute(sql)

            conn.commit()
            conn.close()
            break


def classify_all():

    """Classify all alerts with an UPDATE statement."""

    print ('Classify all unclassified alerts:')
    print ('TODO: I\'m not sure we actually want this (lazy?) option? ')


def main():
   
    """Loop over the menu and display stuff to the user."""

    while True:
        choice = user_menu()

        if choice == 1:
            display_unc()

        if choice == 2:
            display_all()

        if choice == 3:
            classify_alert()

        if choice == 4:
            classify_range()

        if choice == 5:
            classify_all()

        if choice == 6:
            break


if __name__ == "__main__":
    main()
