#include "shared.h"



time_t sched_scan_get_next_time(const sched_scan_config *config){
    if (config->pull_on_start && !config->time_start){
        // If pull on start then initial waiting time is 0
        return 0;
    }

    if (config->scan_day) {
        // Option 1: Day of the month
        int status = -1;
        
        while (status < 0) {
            status = check_day_to_scan(config->scan_day, config->scan_time);
            if (status == 0) {
                // Correct day, sleep until scan_time and then run
                return (time_t) get_time_to_hour(config->scan_time);
            } else {
                // Sleep until next day and re-evaluate
                wm_delay(1000); // Sleep one second to avoid an infinite loop
                const time_t sleep_until_tomorrow = get_time_to_hour("00:00"); 

                mtdebug2(WM_GCP_LOGTAG, "Sleeping for %d seconds.", (int)sleep_until_tomorrow);
                wm_delay(1000 * sleep_until_tomorrow);
            }
        }
    } else if (config->scan_wday >= 0) {
        // Option 2: Day of the week
        return (time_t) get_time_to_day(config->scan_wday, config->scan_time);

    } else if (config->scan_time) {
        // Option 3: Time of the day [hh:mm]
        return (time_t) get_time_to_hour(config->scan_time);
    } else if (config->interval) {
        // Option 4: Interval of time
        
        if(!config->time_start){
            // First time
            return 0;
        }
        const time_t last_run_time = time(NULL) - config->time_start;

        if ((time_t)data->interval >= last_run_time) {
            return  (time_t)data->interval - last_run_time;
        } else {
            mtwarn(WM_GCP_LOGTAG, "Interval overtaken.");
            return 0;
        }
    } else {
        mtinfo(WM_GCP_LOGTAG, "Invalid Scheduling option. Exiting.");
        pthread_exit(NULL);
        
    }
    return 0;
}
