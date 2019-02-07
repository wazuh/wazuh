#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh import common
from io import StringIO
try:
    import configparser
    unicode = str
except ImportError:
    import ConfigParser as configparser


DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"


def totals(year, month, day):
    """
    Returns the totals file.

    :param year: Year in YYYY format, e.g. 2016
    :param month: Month in number or 3 first letters, e.g. Feb or 2
    :param day: Day, e.g. 9
    :return: Array of dictionaries. Each dictionary represents an hour.
    """

    try:
        year = int(year)
        day = int(day)

        if year < 0 or day < 0 or day > 31:
            raise WazuhException(1307)

        day = "%02d" % day
    except ValueError:
        raise WazuhException(1307)

    if month not in MONTHS:
        try:
            index = int(month)
        except ValueError:
            raise WazuhException(1307)

        if index < 1 or index > 12:
            raise WazuhException(1307)

        try:
            month = MONTHS[index - 1]
        except IndexError:
            raise WazuhException(1307)

    try:
        stat_filename = common.stats_path + "/totals/" + str(year) + '/' + month + "/ossec-totals-" + day + ".log"
        stats = open(stat_filename, 'r')
    except IOError:
        raise WazuhException(1308, stat_filename)

    response = []
    alerts = []

    for line in stats:
        data = line.split('-')

        if len(data) == 4:
            hour = int(data[0])
            sigid = int(data[1])
            level = int(data[2])
            times = int(data[3])

            alert = {'sigid': sigid, 'level': level, 'times': times}
            alerts.append(alert)
        else:
            data = line.split('--')

            if len(data) != 5:
                if len(data) in (0, 1):
                    continue
                else:
                    raise WazuhException(1309)

            hour = int(data[0])
            total_alerts = int(data[1])
            events = int(data[2])
            syscheck = int(data[3])
            firewall = int(data[4])

            response.append({'hour': hour, 'alerts': alerts, 'totalAlerts': total_alerts, 'events': events, 'syscheck': syscheck, 'firewall': firewall})
            alerts = []

    return response


def hourly():
    """
    Returns the hourly averages.

    :return: Dictionary: averages and interactions.
    """

    averages = []
    interactions = 0

    # What's the 24 for?
    for i in range(25):
        try:
            hfile = open(common.stats_path + '/hourly-average/' + str(i))
            data = hfile.read()

            if i == 24:
                interactions = int(data)
            else:
                averages.append(int(data))

            hfile.close()
        except IOError:
            if i < 24:
                averages.append(0)

    return {'averages': averages, 'interactions': interactions}


def weekly():
    """
    Returns the weekly averages.

    :return: A dictionary for each week day.
    """

    response = {}

    # 0..6 => Sunday..Saturday
    for i in range(7):
        hours = []
        interactions = 0

        for j in range(25):
            try:
                wfile = open(common.stats_path + '/weekly-average/' + str(i) + '/' + str(j))
                data = wfile.read()

                if j == 24:
                    interactions = int(data)
                else:
                    hours.append(int(data))

                wfile.close()
            except IOError:
                if i < 24:
                    hours.append(0)

        response[DAYS[i]] = {'hours': hours, 'interactions': interactions}

    return response


def get_daemons_stats(filename):
    """
    Returns the stats of an input file.

    :param filename: Full path of the file to get information.

    :return: A dictionary with the stats of the input file.
    """
    try:

        with open(filename, 'r') as f:
            input_file = unicode("[root]\n" + f.read())

        fp = StringIO(input_file)
        config = configparser.RawConfigParser()
        config.readfp(fp)
        items = dict(config.items("root"))

        try:
            for key, value in items.items():
                items[key] = float(value[1:-1])  # delete extra quotation marks
        except Exception as e:
            return WazuhException(1104, str(e))

        return items

    except Exception as e:

        raise WazuhException(1308, str(e))


def analysisd():
    """
    Returns the stats of analysisd.

    :return: A dictionary with the stats of analysisd.
    """
    return get_daemons_stats(common.analysisd_stats)


def remoted():
    """
    Returns the stats of remoted.

    :return: A dictionary with the stats of remoted.
        """
    return get_daemons_stats(common.remoted_stats)