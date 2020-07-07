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
 *          "<bucket type=\"config\">\n"
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
