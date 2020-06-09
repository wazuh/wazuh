#include "wmodules_scheduling_helpers.h"
#include <time.h> 

static time_t current_time = 0;
extern time_t __real_time(time_t *_time);
/**************** Mocked functions *************/
/**     Mocked functions       **/

time_t __wrap_time(time_t *_time){
    if(!current_time){
        current_time = __real_time(NULL);
    }
    return current_time;
}

/* Sets current simulation time */
void set_current_time(time_t _time) {
    current_time = _time;
}

void __wrap_w_time_delay(unsigned long int msec){
    current_time += (msec/1000);
}

void __wrap_w_sleep_until(const time_t new_time){
    current_time = new_time;
}


/***************** Helpers  ********************/
/**
 * Receives a string in XML format and returnes it as an xml_node array structure
 * Example:
 *  
 *          "<disabled>no</disabled>\n"
 *          "<interval>10m</interval>\n"
 *          "<run_on_start>yes</run_on_start>\n"
 *          "<skip_on_error>yes</skip_on_error>\n"
 *         "<bucket type=\"config\">\n"
 *          "    <name>wazuh-aws-wodle</name>\n"
 *          "    <path>config</path>\n"
 *          "   <aws_profile>default</aws_profile>\n"
 *          "</bucket>"
 * */
const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml){
    XML_NODE nodes;
    OS_ReadXMLString(string, _lxml);
    nodes = OS_GetElementsbyNode(_lxml, NULL);
    return nodes;
}


/**
 *  Inits a shched_config object based on an xml format string
 *  Example:
 *              "<wday>tuesday</wday>\n"
 *              "<time>0:00</time>"
 * */
sched_scan_config init_config_from_string(const char* string){
    OS_XML _lxml;
    XML_NODE nodes = string_to_xml_node(string, &_lxml);

    sched_scan_config scan_config;
    sched_scan_init(&scan_config);
    sched_scan_read(&scan_config, nodes, "");
    OS_ClearNode(nodes);
    OS_ClearXML(&_lxml);
    return scan_config;
}

/********* Check functions  ********************/
/**
 * Test interval between consecutive runs matches configuration
 * */
void check_time_interval(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES) {
    time_t current = mktime(&date_array[0]);
    int i=1;
    while(i < MAX_DATES) {
        time_t next = mktime(&date_array[i]);
        assert_int_equal( scan_config->interval, next - current);
        current = mktime(&date_array[i++]);
    }
}

/**
 * Test that all executions matches day of the month configuration 
 * */
void check_day_of_month(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES) {
    for (int i = 0; i < MAX_DATES; i++) {
        assert_int_equal( scan_config->scan_day, date_array[i].tm_mday);
        if(i > 0){
            // Assert that months are consecutives
            assert_int_equal((date_array[i-1].tm_mon + 1) % 12, date_array[i].tm_mon);
        }
    }
}

/**
 * Test that all executions matches day of the month configuration 
 * */
void check_day_of_week(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES) {
    for (int i = 0; i < MAX_DATES; i++) {
        assert_int_equal( scan_config->scan_wday, date_array[i].tm_wday);
        if(i > 0){
            // Assert there is one week difference
            if (is_leap_year(date_array[i-1].tm_year)) {
                assert_int_equal((date_array[i-1].tm_yday + 7) % 366, date_array[i].tm_yday);
            } else {
                assert_int_equal((date_array[i-1].tm_yday + 7) % 365, date_array[i].tm_yday);
            }
        }
    }
}

/**
 * Test that all executions matches day of the month configuration 
 * */
void check_time_of_day(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES) {
    for (int i = 0; i < MAX_DATES; i++) {
        char ** parts = OS_StrBreak(':', scan_config->scan_time, 2);
        // Look for the particular hour
        int tm_hour = atoi(parts[0]);
        int tm_min = atoi(parts[1]);
        
        assert_int_equal( tm_hour, date_array[i].tm_hour);
        assert_int_equal( tm_min, date_array[i].tm_min);
        if(i > 0){
            // Assert that there are following days
            if (is_leap_year(date_array[i-1].tm_year)) {
                assert_int_equal((date_array[i-1].tm_yday + 1) % 366, date_array[i].tm_yday);
            } else {
                assert_int_equal((date_array[i-1].tm_yday + 1) % 365, date_array[i].tm_yday);
            }
        }

        free(parts[0]);
        free(parts[1]);
        free(parts);
    }
}
