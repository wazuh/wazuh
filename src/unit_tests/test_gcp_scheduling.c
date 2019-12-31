/**
 * Test corresponding to the scheduling capacities
 * for aws Module
 * 
 * To add this tests on CMAKE:
 *  
 *  list(APPEND tests_names "test_gcp_scheduling")
 *  list(APPEND tests_flags "-Wl,--wrap=time,--wrap=wm_delay,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_exec,--wrap=FOREVER")
 * 
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

static wmodule gcp_module;
static unsigned test_gcp_date_counter = 0;
static struct tm test_gcp_date_storage[TEST_MAX_DATES];
/**
 *  Since module run is in a loop we pass a function ptr 
 * to use when cut condition is met in wrapped funcion
 * */
static void (*check_function_ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES) = 0;

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    // Will wrap this funciont to check running times in order to check scheduling
    time_t current_time = time(NULL);
    struct tm *date = localtime(&current_time);
    test_gcp_date_storage[test_gcp_date_counter++] = *date;
    if(test_gcp_date_counter >= TEST_MAX_DATES){
        const wm_gcp *ptr = (wm_gcp *) gcp_module.data;
        check_function_ptr( &ptr->scan_config, &test_gcp_date_storage[0], TEST_MAX_DATES);
        // Break infinite loop
        disable_forever_loop();
    }
    *exitcode = 0;
    *output = strdup("TEST_STRING");
    return 0;
}

static void set_up_test(void (*ptr)(const sched_scan_config *scan_config, struct tm *date_array, unsigned int MAX_DATES)) {
    if((wm_gcp *) gcp_module.data){
        // Free data to generate a new initialziation between tests
        os_free(gcp_module.data);
        gcp_module.data = NULL;
    }
    enable_forever_loop();
    test_gcp_date_counter = 0;
    check_function_ptr = ptr;
}

static void run_test_string(const char *string){
    OS_XML lxml;
    XML_NODE nodes = string_to_xml_node(string, &lxml);
    assert_int_equal(wm_gcp_read(nodes, &gcp_module),0);
    gcp_module.context->start( (wm_aws *) gcp_module.data);
}


/** Tests **/
void test_interval_execution() {
    set_up_test(check_time_interval);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<interval>2m</interval>\n"
    ;
    run_test_string(string);
}

void test_day_of_month(){
    set_up_test(check_day_of_month);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<day>28</day>\n"
        "<time>0:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    run_test_string(string);
}

void test_day_of_week(){
    set_up_test(check_day_of_week);
    const char *string = 
        "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<wday>Saturday</wday>\n"
        "<time>3:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    run_test_string(string);
}

void test_time_of_day(){
    set_up_test(check_time_of_day);
    const char *string = 
       "<enabled>yes</enabled>\n"
        "<project_id>trial-project-id</project_id>\n"
        "<subscription_name>wazuh</subscription_name>\n"
        "<credentials_file>credentials.json</credentials_file>\n"
        "<max_messages>1</max_messages>\n"
        "<time>18:00</time>\n"
        "<pull_on_start>no</pull_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    run_test_string(string);
}


int main(void) {
    // Create file if is not existent
    FILE *fptr;
    fptr = fopen("/var/ossec/credentials.json", "rb+");
    if(fptr == NULL) //if file does not exist, create it
    {
        fptr = fopen("/var/ossec/credentials.json", "wb");
    } 
    if (fptr) {
        fclose(fptr);
    }
    else {
        print_message("Could not create nor read credentials file! Please run this test as sudo\n");
        exit(1);
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interval_execution),
        cmocka_unit_test(test_day_of_month),
        cmocka_unit_test(test_day_of_week),
        cmocka_unit_test(test_time_of_day),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}