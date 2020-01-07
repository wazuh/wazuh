#include "shared.h"
#include "wazuh_modules/wmodules.h"


static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_DAY = "day";
static const char *XML_WEEK_DAY = "wday";
static const char *XML_TIME = "time";


static int _sched_scan_validate_parameters(sched_scan_config *scan_config);
static time_t _get_next_time(const sched_scan_config *config, const char *MODULE_TAG,  const int run_on_start);

/**
 * Initializes sched_scan_config structure with 
 * default values
 * */
void sched_scan_init(sched_scan_config *scan_config){
    scan_config->scan_wday = -1;
    scan_config->scan_day = 0;
    scan_config->scan_time = NULL;
    scan_config->interval = WM_DEF_INTERVAL / 2;
    scan_config->month_interval = false;
    scan_config->time_start = 0;
}

/**
 * Reads an array of xml nodes and overrides scheduling configuration
 * Expected xml nodes:
 * ´´´
 * <day></day>
 * <wday></wday>
 * <time></time>
 * <interval></interval>
 * ´´´
 * */
int sched_scan_read(sched_scan_config *scan_config, xml_node **nodes, const char *MODULE_NAME) {
    unsigned i;
    for (i = 0; nodes[i]; i++) {
        if (!strcmp(nodes[i]->element, XML_SCAN_DAY)) { // <day></day>
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            } else {
                scan_config->scan_day = atoi(nodes[i]->content);
                if (scan_config->scan_day < 1 || scan_config->scan_day > 31) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                    return (OS_INVALID);
                }
            }
        } else if (!strcmp(nodes[i]->element, XML_WEEK_DAY)) { // <wday></wday>
            scan_config->scan_wday = w_validate_wday(nodes[i]->content);
            if (scan_config->scan_wday < 0 || scan_config->scan_wday > 6) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_TIME)) {  // <time></time>
            scan_config->scan_time = w_validate_time(nodes[i]->content);
            if (!scan_config->scan_time) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) { //<interval></interval>
            char *endptr;
            scan_config->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (scan_config->interval <= 0 || scan_config->interval >= UINT_MAX) {
                merror("Invalid interval value at module '%s'", MODULE_NAME);
                return OS_INVALID;
            }

            switch (*endptr) {
                case 'M':
                    scan_config->month_interval = true;
                    // interval will be considered as a month when this option is active
                    break;
                case 'w':
                    scan_config->interval *= 604800;
                    break;
                case 'd':
                    scan_config->interval *= 86400;
                    break;
                case 'h':
                    scan_config->interval *= 3600;
                    break;
                case 'm':
                    scan_config->interval *= 60;
                    break;
                case 's':
                case '\0':
                    break;
                default:
                    merror("Invalid interval value at module '%s'", MODULE_NAME);
                    return OS_INVALID;
            }
        }
    }

    return _sched_scan_validate_parameters(scan_config);
}

/**
 * Calculates the next scheduling time according to module scheduling configuration
 * Available options are:
 * 1. Specific day of a month 
 * 2. Specific day of a week
 * 3. Every day at a certain time
 * 4. Set up a scan between intervals
 * @param config Scheduling configuration
 * @param MODULE_TAG String to identify module
 * @param run_on_start forces first time run
 * @return remaining time until next scan
 * */
time_t sched_scan_get_next_time(sched_scan_config *config, const char *MODULE_TAG,  const int run_on_start) {
    const time_t next_time = _get_next_time(config, MODULE_TAG, run_on_start);
    config->time_start = time(NULL) + next_time;
    return next_time;
}

static time_t _get_next_time(const sched_scan_config *config, const char *MODULE_TAG,  const int run_on_start) {
    if (run_on_start && !config->time_start) {
        // If scan on start then initial waiting time is 0
        return 0;
    }

    if (config->scan_day) {
        // Option 1: Day of the month
        int status = -1;
        int avoid_repeated_scan = 0;
        int month_counter = config->interval; // To check correct month
        while (status < 0 || !avoid_repeated_scan) {
            status = check_day_to_scan(config->scan_day, config->scan_time);
            //At least a day from the last scan
            avoid_repeated_scan = (time(NULL) - config->time_start) > 86400;
            if ( (status == 0) && (month_counter <= 1) && avoid_repeated_scan) {
                // Correct day, sleep until scan_time and then run
                return (time_t) get_time_to_hour(config->scan_time);
            } else {
                if (status == 0 && avoid_repeated_scan) {
                    // Correct day, but incorrect month
                    month_counter--;
                }
                // Sleep until next day and re-evaluate
                wm_delay(1000); // Sleep one second to avoid an infinite loop
                const time_t sleep_until_tomorrow = get_time_to_hour("00:00"); 

                mtdebug2(MODULE_TAG, "Sleeping for %d seconds.", (int)sleep_until_tomorrow);
                wm_delay(1000 * sleep_until_tomorrow);
            }
        }
    } else if (config->scan_wday >= 0) {
        // Option 2: Day of the week
        if(time(NULL) - config->time_start < 3600){
            // Sleep an hour
            wm_delay(3600000);
        }
        return (time_t) get_time_to_day(config->scan_wday, config->scan_time);

    } else if (config->scan_time) {
        // Option 3: Time of the day [hh:mm]
        if(time(NULL) - config->time_start < 3600){
            // Sleep an hour
            wm_delay(3600000);
        }
        return (time_t) get_time_to_hour(config->scan_time);
    } else if (config->interval) {
        // Option 4: Interval of time
        
        if(!config->time_start){
            // First time
            return 0;
        }
        const time_t last_run_time = time(NULL) - config->time_start;

        if ((time_t)config->interval >= last_run_time) {
            return  (time_t)config->interval - last_run_time;
        } else {
            mtwarn(MODULE_TAG, "Interval overtaken.");
            return 0;
        }
    } else {
        mterror(MODULE_TAG, "Invalid Scheduling option. Exiting.");
        pthread_exit(NULL);
        
    }
    return 0;
}


int _sched_scan_validate_parameters(sched_scan_config *scan_config) {
    // Validate scheduled scan parameters and interval value
    if (scan_config->scan_day && (scan_config->scan_wday >= 0)) {
        merror("Options 'day' and 'wday' are not compatible.");
        return OS_INVALID;
    } else if (scan_config->scan_day) {
        if (!scan_config->month_interval) {
            mwarn("Interval must be a multiple of one month. New interval value: 1M");
            scan_config->interval = 1; // 1 month
            scan_config->month_interval = true;
        }
        if (scan_config->scan_time)
            scan_config->scan_time = strdup("00:00");
    } else if (scan_config->scan_wday >= 0) {
        if (w_validate_interval(scan_config->interval, 1) != 0) {
            scan_config->interval = 604800;  // 1 week
            mwarn("Interval must be a multiple of one week. New interval value: 1w");
        }
        if (scan_config->interval == 0)
            scan_config->interval = 604800;
        if (!scan_config->scan_time)
            scan_config->scan_time = strdup("00:00");
    } else if (scan_config->scan_time) {
        if (w_validate_interval(scan_config->interval, 0) != 0) {
            scan_config->interval = WM_DEF_INTERVAL;  // 1 day
            mwarn("Interval must be a multiple of one day. New interval value: 1d");
        }
    } else if (scan_config->month_interval) {
        mwarn("Interval value is in months. Setting scan day to first day of the month");
        scan_config->scan_day = 1;
        scan_config->scan_time = strdup("00:00");
    }

    return 0;
}

void sched_scan_dump(const sched_scan_config* scan_config, cJSON *cjson_object){
    if (scan_config->interval) cJSON_AddNumberToObject(cjson_object, "interval", scan_config->interval);
    if (scan_config->scan_day) cJSON_AddNumberToObject(cjson_object, "day", scan_config->scan_day);
    switch (scan_config->scan_wday) {
        case 0:
            cJSON_AddStringToObject(cjson_object, "wday", "sunday");
            break;
        case 1:
            cJSON_AddStringToObject(cjson_object, "wday", "monday");
            break;
        case 2:
            cJSON_AddStringToObject(cjson_object, "wday", "tuesday");
            break;
        case 3:
            cJSON_AddStringToObject(cjson_object, "wday", "wednesday");
            break;
        case 4:
            cJSON_AddStringToObject(cjson_object, "wday", "thursday");
            break;
        case 5:
            cJSON_AddStringToObject(cjson_object, "wday", "friday");
            break;
        case 6:
            cJSON_AddStringToObject(cjson_object, "wday", "saturday");
            break;
        default:
            break;
    }
    if (scan_config->scan_time) cJSON_AddStringToObject(cjson_object, "time", scan_config->scan_time);

}
