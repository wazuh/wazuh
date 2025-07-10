/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "analysisd.h"
#include "stats.h"
#include "rules.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"
#include "headers/file_op.h"
#include "alerts/alerts.h"
#include "headers/debug_op.h"

/* Global definition */
char __stats_comment[192]; // Buffer to store comments for statistics-related alerts.

static const char *(weekdays[]) = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
                      "Friday", "Saturday"
                     };

static const char *(l_month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                     "Sep", "Oct", "Nov", "Dec"
                    };

/* Global variables */

/* Hour 25 is internally used for storing the number of times the stats for that hour have been updated */
static int _RWHour[7][25]; // Expected (Reference) weekly hourly event counts. [day_of_week][hour_of_day]
static int _CWHour[7][25]; // Current weekly hourly event counts. [day_of_week][hour_of_day]

static int _RHour[25]; // Expected (Reference) daily hourly event counts. [hour_of_day]
static int _CHour[25]; // Current daily hourly event counts. [hour_of_day]

static int _cignorehour = 0;  // Hour for which alerts are currently being ignored (to prevent flood).
static int _fired = 0;        // Flag indicating if a statistics-based alert has been fired for the current hour.
static int _daily_errors = 0; // Counter for the number of times thresholds have been exceeded in a day.
int maxdiff = 0;              // Maximum allowed difference for threshold calculation.
int mindiff = 0;              // Minimum allowed difference for threshold calculation.
int percent_diff = 20;        // Percentage difference used for threshold calculation.

/* Last msgs, to avoid floods */
static char ** _lastmsg = NULL;   // Stores the last message processed by each thread.
static char ** _prevlast = NULL;  // Stores the second to last message processed by each thread.
static char ** _pprevlast = NULL; // Stores the third to last message processed by each thread.

/* Msg mutex*/
static pthread_mutex_t msg_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex to protect access to _lastmsg, _prevlast, _pprevlast.

/**
 * @brief Prints the total number of events received per hour for the previous day.
 *
 * This function is called daily. It creates a log file in the STATSAVED directory,
 * structured by year and month, and writes the hourly totals and the overall daily total.
 * The log file is named ossec-totals-DD.log, where DD is the day of the month.
 */
static void print_totals(void) {
    int i, totals = 0;
    char logfile[OS_FLSIZE + 1];
    FILE * flog;

    // Construct the directory path for the previous year's stats.
    snprintf(logfile, OS_FLSIZE, "%s/%d/", STATSAVED, prev_year);
    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, logfile, errno, strerror(errno));
            return;
        }

    // Construct the directory path for the previous month's stats within the year's directory.
    snprintf(logfile, OS_FLSIZE, "%s/%d/%s", STATSAVED, prev_year, prev_month);

    if (IsDir(logfile) == -1)
        if (mkdir(logfile, 0770) == -1) {
            merror(MKDIR_ERROR, logfile, errno, strerror(errno));
            return;
        }

    // Construct the full path for the daily totals log file.
    snprintf(logfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             STATSAVED,
             prev_year,
             prev_month,
             "totals",
             today); // `today` here refers to the day for which totals are being written (effectively previous day's data).

    flog = wfopen(logfile, "a");
    if (!flog) {
        merror(FOPEN_ERROR, logfile, errno, strerror(errno));
        return;
    }

    /* Print the hourly stats */
    for (i = 0; i <= 23; i++) {
        fprintf(flog, "Hour totals - %d:%d\n", i, _CHour[i]); // Write hourly count.
        totals += _CHour[i];                                  // Accumulate total.
    }
    fprintf(flog, "Total events for day:%d\n", totals); // Write daily total.

    fclose(flog);
}

/**
 * @brief Calculates a threshold based on an event number and configured differences.
 *
 * The threshold is calculated as event_number + (event_number * percent_diff / 100).
 * The added difference is capped by `maxdiff` and floored by `mindiff`.
 *
 * @param event_number The base number of events.
 * @return The calculated threshold.
 */
static int gethour(int event_number)
{
    int event_diff;

    // Calculate the percentage-based difference.
    event_diff = (event_number * percent_diff) / 100;
    event_diff++;

    // Apply minimum and maximum difference constraints.
    if (event_diff < mindiff) {
        return (event_number + mindiff);
    } else if (event_diff > maxdiff) {
        return (event_number + maxdiff);
    }

    return (event_number + event_diff);
}

/**
 * @brief Updates the hourly and weekly statistics at the end of a day.
 *
 * This function is called daily. It performs the following actions:
 * 1. Calls `print_totals()` to log the event counts for the completed day.
 * 2. Updates the reference hourly counts (`_RHour`) based on the current hourly counts (`_CHour`)
 *    and the number of previous updates.
 * 3. Writes the updated reference hourly counts to files in the `STATQUEUE` directory.
 * 4. Resets the current hourly counts (`_CHour`) to zero.
 * 5. Updates the reference weekly/hourly counts (`_RWHour`) based on the current weekly/hourly
 *    counts (`_CWHour`) and the number of previous updates for that specific day and hour.
 * 6. Writes the updated reference weekly/hourly counts to files in the `STATWQUEUE` directory.
 * 7. Resets the current weekly/hourly counts (`_CWHour`) to zero.
 * 8. Resets the `_daily_errors` counter.
 */
void Update_Hour()
{
    int i, j;
    int inter;  // Interaction counter, determines how much weight is given to historical data.

    /* Print total number of logs received per hour */
    print_totals();

    /* Hourly update */
    _RHour[24]++; // Increment the interaction count for daily stats (stored at index 24).
    inter = _RHour[24];
    // Cap interaction count at 7 to prevent old data from having too much influence.
    if (inter > 7) {
        inter = 7;
    }

    // Loop through hours 0-23 and the interaction counter at 24.
    for (i = 0; i <= 24; i++) {
        char _hourly[128]; /* _hourly file */

        FILE *fp;

        // Process actual hour data (0-23).
        if (i != 24) {
            /* If saved hourly = 0, just copy the current hourly rate */
            // If no events were recorded for this hour, skip updating its reference.
            if (_CHour[i] == 0) {
                continue;
            }

            // If this is the first time data is recorded for this hour, initialize reference.
            if (_RHour[i] == 0) {
                _RHour[i] = _CHour[i] + 20; // Initialize with current count + a buffer (?)
            }

            else {
                /* If we had too many errors this day */
                // Adjust the averaging formula based on whether daily error thresholds were frequently hit.
                if (_daily_errors >= 3) {
                    // Give more weight to current data if many errors occurred.
                    _RHour[i] = (((3 * _CHour[i]) + (inter * _RHour[i])) / (inter + 3)) + 25;
                }

                else {
                    /* The average is going to be the number of interactions +
                     * the current hourly rate, divided by 4 */
                    _RHour[i] = ((_CHour[i] + (inter * _RHour[i])) / (inter + 1)) + 5;
                }
            }
        }

        // Persist the updated reference hourly count.
        snprintf(_hourly, 128, "%s/%d", STATQUEUE, i);
        fp = wfopen(_hourly, "w");
        if (fp) {
            fprintf(fp, "%d", _RHour[i]);
            fclose(fp);
        }

        else {
            mterror("logstats", FOPEN_ERROR, _hourly, errno, strerror(errno));
        }

        _CHour[i] = 0; /* Zero the current hour */
    }

    // Loop through days of the week (0-6).
    for (i = 0; i <= 6; i++) {
        char _weekly[128];
        FILE *fp;

        _CWHour[i][24]++;  // Increment interaction count for this day of the week.
        inter = _CWHour[i][24];
        if (inter > 7) { // Cap interaction count at 7.
            inter = 7;
        }

        // Loop through hours 0-23 and interaction counter at 24 for this day.
        for (j = 0; j <= 24; j++) {
            if (j != 24) {  // Process actual hour data (0-23).
                if (_CWHour[i][j] == 0) {
                    continue;  // If no events for this specific hour of this day, skip.
                }

                // Initialize reference if it's the first time.
                if (_RWHour[i][j] == 0) {
                    _RWHour[i][j] = _CWHour[i][j] + 20;
                }

                else {
                    // Adjust averaging based on daily errors.
                    if (_daily_errors >= 3) {
                        _RWHour[i][j] = (((3 * _CWHour[i][j]) + (inter * _RWHour[i][j])) / (inter + 3)) + 25;
                    } else {
                        _RWHour[i][j] = ((_CWHour[i][j] + (inter * _RWHour[i][j])) / (inter + 1)) + 5;
                    }
                }
            }

            snprintf(_weekly, 128, "%s/%d/%d", STATWQUEUE, i, j);
            fp = wfopen(_weekly, "w");
            if (fp) {
                fprintf(fp, "%d", _RWHour[i][j]);
                fclose(fp);
            } else {
                mterror("logstats", FOPEN_ERROR, _weekly, errno, strerror(errno));
            }

            _CWHour[i][j] = 0;
        }
    }

    _daily_errors = 0; // Reset daily error counter for the new day.
}

/**
 * @brief Checks if the current event counts exceed predefined statistical thresholds.
 *
 * This function is called for each event. It increments the current hourly (`_CHour`)
 * and weekly-hourly (`_CWHour`) event counts.
 * It then checks if these counts surpass the calculated thresholds based on `_RHour`
 * (average hourly rate) and `_RWHour` (average rate for this specific hour on this
 * day of the week).
 *
 * Conditions for checking:
 * - At least 2 days of stats must have been collected (`_RHour[24] > 2`).
 * - If `_daily_errors` >= 3, no more alerts for this day.
 * - If an alert was already fired (`_fired == 1`) for the current hour (`_cignorehour == __crt_hour`),
 *   no more alerts for this hour.
 * - If the current hour is different from `_cignorehour`, reset `_fired` and update `_cignorehour`.
 *
 * If a threshold is exceeded:
 * - A descriptive message is formatted into `__stats_comment`.
 * - `_fired` is set to 1.
 * - `_daily_errors` is incremented.
 * - The function returns 1 (indicating an alert should be generated).
 *
 * @return 1 if a threshold is exceeded, 0 otherwise.
 */
int Check_Hour()
{
    // Increment current event counts for the current hour and day of the week.
    _CHour[__crt_hour]++;
    _CWHour[__crt_wday][__crt_hour]++;

    // We need at least 2 full days of stats before we start alerting.
    // _RHour[24] stores the number of times Update_Hour has run for daily stats.
    if (_RHour[24] <= 2) {
        return (0);
    }

    // Suppress alerts if too many errors today or if an alert already fired for this specific hour.
    if ((_daily_errors >= 3) || ((_fired == 1) && (_cignorehour == __crt_hour))) {
        return (0);
    } else if (_cignorehour != __crt_hour) {
        // If it's a new hour, reset the fired flag and update the hour being ignored.
        _cignorehour = __crt_hour;
        _fired = 0;
    }

    /* Check if passed the threshold for general hourly average */
    if (_RHour[__crt_hour] != 0) { // Check only if there's a reference value.
        // First check: current count > reference count.
        if (_CHour[__crt_hour] > (_RHour[__crt_hour])) {
            // Second check: current count > calculated threshold (reference + percentage diff).
            if (_CHour[__crt_hour] > (gethour(_RHour[__crt_hour]))) {
                /* snprintf will null terminate */
                snprintf(__stats_comment, 191,
                         "The average number of logs"
                         " between %d:00 and %d:00 is %d. We "
                         "reached %d.", __crt_hour, __crt_hour + 1,
                         _RHour[__crt_hour], _CHour[__crt_hour]);

                _fired = 1;      // Mark that an alert has been fired for this hour.
                _daily_errors++; // Increment daily error count.
                return (1);
            }
        }
    }

    /* We need to have at least 3 days of stats */
    // _RWHour[__crt_wday][24] stores interaction count for this specific day of week.
    if (_RWHour[__crt_wday][24] <= 2) {
        return (0); // Not enough data for weekly pattern analysis.
    }

    /* Check for the hour during a specific day of the week */
    if (_RWHour[__crt_wday][__crt_hour] != 0) { // Check only if there's a reference value.
        // First check: current count for this day/hour > reference count for this day/hour.
        if (_CWHour[__crt_wday][__crt_hour] > _RWHour[__crt_wday][__crt_hour]) {
            // Second check: current count > calculated threshold for this day/hour.
            if (_CWHour[__crt_wday][__crt_hour] > gethour(_RWHour[__crt_wday][__crt_hour])) {
                snprintf(__stats_comment, 191,
                         "The average number of logs"
                         " between %d:00 and %d:00 on %s is %d. We"
                         " reached %d.", __crt_hour, __crt_hour + 1,
                         weekdays[__crt_wday],
                         _RWHour[__crt_wday][__crt_hour],
                         _CWHour[__crt_wday][__crt_hour]);

                _fired = 1;      // Mark that an alert has been fired for this hour.
                _daily_errors++; // Increment daily error count.
                return (1);
            }
        }
    }
    return (0);
}

/**
 * @brief Initializes directories required for statistics and loads existing statistics data.
 *
 * This function creates the `STATWQUEUE`, `STATQUEUE`, and `STATSAVED` directories if they
 * do not exist. It then attempts to load previously saved hourly (`_RHour`) and
 * weekly-hourly (`_RWHour`) reference counts from files within these directories.
 * If files are not found or cannot be read, the corresponding counts are initialized to 0.
 * Current counts (`_CHour`, `_CWHour`) are initialized to 0.
 *
 * @return 0 on success, -1 on failure to create a directory.
 */
int Init_Stats_Directories(){
    int i = 0;
    int j = 0;

    // Create STATWQUEUE directory (for weekly/hourly reference counts).
    if (IsDir(STATWQUEUE) == -1) {
        if (mkdir(STATWQUEUE, 0770) == -1) {
            mterror("logstats", "Unable to create stat queue: %s", STATWQUEUE);
            return (-1);
        }
    }

    // Create STATQUEUE directory (for daily/hourly reference counts).
    if (IsDir(STATQUEUE) == -1) {
        if (mkdir(STATQUEUE, 0770) == -1) {
            mterror("logstats", "Unable to create stat queue: %s", STATQUEUE);
            return (-1);
        }
    }

    // Create STATSAVED directory (for historical daily totals).
    if (IsDir(STATSAVED) == -1) {
        if (mkdir(STATSAVED, 0770) == -1) {
            mterror("logstats", "Unable to create stat directory: %s", STATSAVED);
            return (-1);
        }
    }

    /* Create hourly directory (24 hour is the stats) */
    // Load or initialize daily/hourly reference counts (_RHour).
    for (i = 0; i <= 24; i++) {
        char _hourly[128];
        snprintf(_hourly, 128, "%s/%d", STATQUEUE, i);

        _CHour[i] = 0;
        if (File_DateofChange(_hourly) < 0) {
            _RHour[i] = 0;
        }

        else {
            FILE *fp;
            fp = wfopen(_hourly, "r");
            if (!fp) {
                _RHour[i] = 0;
            } else {
                if (fscanf(fp, "%d", &_RHour[i]) <= 0) {
                    _RHour[i] = 0;
                }

                if (_RHour[i] < 0) {
                    _RHour[i] = 0;
                }
                fclose(fp);
            }
        }
    }

    /* Create weekly/hourly directories */
    for (i = 0; i <= 6; i++) {
        char _weekly[128];
        snprintf(_weekly, 128, "%s/%d", STATWQUEUE, i);
        if (IsDir(_weekly) == -1)
            if (mkdir(_weekly, 0770) == -1) {
                mterror("logstats", "Unable to create stat queue: %s", _weekly);
                return (-1);
            }

        for (j = 0; j <= 24; j++) {
            _CWHour[i][j] = 0;
            snprintf(_weekly, 128, "%s/%d/%d", STATWQUEUE, i, j);
            if (File_DateofChange(_weekly) < 0) {
                _RWHour[i][j] = 0;
            } else {
                FILE *fp;
                fp = wfopen(_weekly, "r");
                if (!fp) {
                    _RWHour[i][j] = 0;
                } else {
                    if (fscanf(fp, "%d", &_RWHour[i][j]) <= 0) {
                        _RWHour[i][j] = 0;
                    }

                    if (_RWHour[i][j] < 0) {
                        _RWHour[i][j] = 0;
                    }
                    fclose(fp);
                }
            }
        }
    }
    return 0;
}


/**
 * @brief Initializes statistics-related variables for a specific analysis thread.
 *
 * This function performs the following initializations:
 * 1. Allocates memory for `_lastmsg`, `_prevlast`, and `_pprevlast` arrays if they
 *    haven't been allocated yet (thread-safe). These arrays are used to prevent
 *    log flooding by tracking recent messages per thread.
 * 2. Calls `Start_Time()` to initialize global time-related variables.
 * 3. Clears the `__stats_comment` buffer.
 * 4. Retrieves configuration values for `stats_maxdiff`, `stats_mindiff`, and
 *    `stats_percent_diff` from the `analysisd` configuration section.
 * 5. Initializes the per-thread message history (`_lastmsg[t_id]`, etc.) to empty strings.
 *
 * @param t_id The ID of the current analysis thread.
 * @param threads_number The total number of analysis threads.
 * @return Always returns 0.
 */
int Start_Hour(int t_id, int threads_number)
{

    w_mutex_lock(&msg_mutex);
    if (!_lastmsg) {
        os_calloc(threads_number, sizeof(char *), _lastmsg);
        os_calloc(threads_number, sizeof(char *), _prevlast);
        os_calloc(threads_number, sizeof(char *), _pprevlast);
    }
    w_mutex_unlock(&msg_mutex);

    Start_Time();

    /* Clear some memory */
    memset(__stats_comment, '\0', 192);

    /* Get maximum/minimum diffs */
    maxdiff = getDefine_Int("analysisd",
                            "stats_maxdiff",
                            10, 999999);

    mindiff = getDefine_Int("analysisd",
                            "stats_mindiff",
                            10, 999999);

    percent_diff = getDefine_Int("analysisd",
                                 "stats_percent_diff",
                                 5, 9999);

    /* Last three messages
     * They are used to keep track of the last
     * messages received to avoid floods
     */
    _lastmsg[t_id] = NULL;
    _prevlast[t_id] = NULL;
    _pprevlast[t_id] = NULL;

    /* They should not be null */
    os_strdup(" ", _lastmsg[t_id]);
    os_strdup(" ", _prevlast[t_id]);
    os_strdup(" ", _pprevlast[t_id]);

    return (0);
}

/**
 * @brief Initializes global time-related variables.
 *
 * Sets `today`, `thishour`, `prev_year`, and `prev_month` based on the current system time.
 * Also resets `_fired` and `_cignorehour` flags related to alert suppression.
 * `c_time` (current time as time_t) is assumed to be globally available and updated elsewhere.
 */
void Start_Time(){
    struct tm tm_result = { .tm_sec = 0 };

    /* Current time */
    localtime_r(&c_time, &tm_result);

    /* Other global variables */
    _fired = 0;
    _cignorehour = 0;

    today = tm_result.tm_mday;
    thishour = tm_result.tm_hour;
    prev_year = tm_result.tm_year + 1900;
    strncpy(prev_month, l_month[tm_result.tm_mon], 3);
    prev_month[3] = '\0';

}
