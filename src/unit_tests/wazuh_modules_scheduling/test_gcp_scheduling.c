/**
 * Test corresponding to the scheduling capacities
 * for gcp Module
 * */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h> 
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_gcp.h"
#include "wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *gcp_module;
static OS_XML *lxml;

static unsigned test_gcp_date_counter = 0;
static struct tm test_gcp_date_storage[TEST_MAX_DATES];

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_gcp_date_storage[test_gcp_date_counter++] = *date;
    if(test_gcp_date_counter >= TEST_MAX_DATES){
        const wm_gcp *ptr = (wm_gcp *) gcp_module->data;
        check_function_ptr( &ptr->scan_config, &test_gcp_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    *exitcode = 0;
    *output = strdup("TEST_STRING");
    return 0;
}

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    enable_forever_loop();
    test_gcp_date_counter = 0;
    check_function_ptr = ptr;
}

static void wmodule_cleanup(wmodule *module){
    wm_gcp* module_data = (wm_gcp *)module->data;
    free(module_data->project_id);
    free(module_data->credentials_file);
    free(module_data->subscription_name);
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    // Create file if is not existent
    FILE *fptr;
    fptr = fopen("/var/ossec/credentials.json", "rb+");
    if(fptr == NULL) {
        fptr = fopen("/var/ossec/credentials.json", "wb");
    }
    if (fptr) {
        fclose(fptr);
    } else {
        print_message("Could not create nor read credentials file! Please run this test as sudo\n");
        exit(1);
    }

    gcp_module = calloc(1, sizeof(wmodule));
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<interval>2m</interval>\n"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    assert_int_equal(wm_gcp_read(nodes, gcp_module), 0);
    OS_ClearNode(nodes);
    return 0;
}

static int teardown_module(){
    wmodule_cleanup(gcp_module);
    OS_ClearXML(lxml);
    return 0;
}

/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;
    gcp_module->context->start(module_data);
}

void test_day_of_month(){
    set_up_test(check_day_of_month);
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 13;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 1; // 1 month
    module_data->scan_config.month_interval = true;
    gcp_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_day_of_week(){
    set_up_test(check_day_of_week);
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = 4;
    module_data->scan_config.scan_time = strdup("00:00");
    module_data->scan_config.interval = 604800;  // 1 week
    module_data->scan_config.month_interval = false;
    gcp_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}

void test_time_of_day(){
    set_up_test(check_time_of_day);
    wm_gcp* module_data = (wm_gcp *)gcp_module->data;
    module_data->scan_config.last_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.scan_time = strdup("05:25");
    module_data->scan_config.interval = WM_DEF_INTERVAL;  // 1 day
    module_data->scan_config.month_interval = false;
    gcp_module->context->start(module_data);
    free(module_data->scan_config.scan_time);
}


void test_fake_tag(){
    const char *string = 
       "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<time>18:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<tag>yes</tag>"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_gcp_read(nodes, module),-1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wm_gcp *module_data = (wm_gcp*) module->data;
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_monthday_configuration() {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<day>6</day>\n"
        "<time>11:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_gcp_read(nodes, module),0);
    wm_gcp *module_data = (wm_gcp*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 6);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "11:00");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_weekday_configuration() {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<wday>Sunday</wday>\n"
        "<time>23:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_gcp_read(nodes, module),0);
    wm_gcp *module_data = (wm_gcp*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 0);
    assert_string_equal(module_data->scan_config.scan_time, "23:00");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_daytime_configuration() {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<time>21:43</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_gcp_read(nodes, module),0);
    wm_gcp *module_data = (wm_gcp*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "21:43");
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    free(module_data->scan_config.scan_time);
    wmodule_cleanup(module);
}

void test_read_scheduling_interval_configuration() {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<interval>24h</interval>\n"
        "<pull_on_start>no</pull_on_start>\n"
    ;
    wmodule *module = calloc(1, sizeof(wmodule));;
    OS_XML xml;
    XML_NODE nodes = string_to_xml_node(string, &xml);
    assert_int_equal(wm_gcp_read(nodes, module),0);
    wm_gcp *module_data = (wm_gcp*) module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
    wmodule_cleanup(module);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test(test_interval_execution),
        cmocka_unit_test(test_day_of_month),
        cmocka_unit_test(test_day_of_week),
        cmocka_unit_test(test_time_of_day)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test(test_fake_tag),
        cmocka_unit_test(test_read_scheduling_monthday_configuration),
        cmocka_unit_test(test_read_scheduling_weekday_configuration),
        cmocka_unit_test(test_read_scheduling_daytime_configuration),
        cmocka_unit_test(test_read_scheduling_interval_configuration)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result &= cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
