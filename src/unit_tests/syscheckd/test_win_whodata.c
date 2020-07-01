/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winevt.h>

#include "syscheckd/syscheck.h"
#include "unit_tests/wrappers/syscheckd/win_whodata.h"

extern int set_winsacl(const char *dir, int position);
extern int set_privilege(HANDLE hdle, LPCTSTR privilege, int enable);
extern char *get_whodata_path(const short unsigned int *win_path);
extern int whodata_path_filter(char **path);
extern void whodata_adapt_path(char **path);
extern int whodata_check_arch();
extern int is_valid_sacl(PACL sacl, int is_file);
extern void replace_device_path(char **path);
extern int get_drive_names(wchar_t *volume_name, char *device);
extern int get_volume_names();
extern void notify_SACL_change(char *dir);
extern int whodata_hash_add(OSHash *table, char *id, void *data, char *tag);
extern void restore_sacls();
extern int restore_audit_policies();
extern void audit_restore();
extern int check_object_sacl(char *obj, int is_file);
extern void whodata_clist_remove(whodata_event_node *node);
extern void free_win_whodata_evt(whodata_evt *evt);
extern int compare_timestamp(SYSTEMTIME *t1, SYSTEMTIME *t2);
extern int get_file_time(unsigned long long file_time_val, SYSTEMTIME *system_time);
extern void set_subscription_query(wchar_t *query);
extern int set_policies();
extern void whodata_list_set_values();
extern void whodata_list_remove_multiple(size_t quantity);
extern whodata_event_node *whodata_list_add(char *id);
unsigned long WINAPI whodata_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, __attribute__((unused)) void *_void, EVT_HANDLE event);
extern int whodata_audit_start();

void __real_free_whodata_event(whodata_evt *w_evt);

extern char sys_64;
extern PSID everyone_sid;
extern size_t ev_sid_size;
extern int restore_policies;
extern EVT_HANDLE context;

extern const wchar_t* event_fields[];
static int unit_testing = 0;
static int OSHash_Add_ex_check_data = 1;
/**************************************************************************/
/*************************WRAPS - FIXTURES*********************************/
int test_group_setup(void **state) {
    int ret;

    expect_string(__wrap__mdebug1, formatted_msg, "(6287): Reading configuration file: 'test_syscheck.conf'");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node test_$");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node test_$ OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 1");
    expect_string(__wrap__mdebug1, formatted_msg, "(6208): Reading Client Configuration [test_syscheck.conf]");

    ret = Read_Syscheck_Config("test_syscheck.conf");

    unit_testing = 1;
    return ret;
}

static int test_group_teardown(void **state) {
    unit_testing = 0;
    return 0;
}

static int teardown_string(void **state) {
    if(*state)
        free(*state);

    return 0;
}

static int teardown_wdata_device() {
    free_strarray(syscheck.wdata.device);
    free_strarray(syscheck.wdata.drive);

    syscheck.wdata.device = NULL;
    syscheck.wdata.drive = NULL;

    return 0;
}

static int setup_replace_device_path(void **state) {
    syscheck.wdata.device = calloc(10, sizeof(char*));
    syscheck.wdata.drive = calloc(10, sizeof(char *));

    if(syscheck.wdata.device == NULL || syscheck.wdata.drive == NULL)
        return -1;

    return 0;
}

static int teardown_replace_device_path(void **state) {
    if(teardown_wdata_device(state))
        return -1;

    if(teardown_string(state))
        return -1;

    return 0;
}

static int setup_w_clist_single_node(void **state) {
    whodata_event_node *node = calloc(1, sizeof(whodata_event_node));

    if(!node)
        return -1;

    node->next = NULL;
    node->prev = NULL;

    if(node->id = strdup("First node"), !node->id)
        return -1;

    syscheck.w_clist.first = node;
    syscheck.w_clist.last = node;
    syscheck.w_clist.current_size = 1;

    return 0;
}

static int teardown_w_clist_single_node(void **state) {
    if(syscheck.w_clist.first) {
        if(syscheck.w_clist.first->id)
            free(syscheck.w_clist.first->id);

        free(syscheck.w_clist.first);
    }

    syscheck.w_clist.last = syscheck.w_clist.first = NULL;

    return 0;
}

static int setup_w_clist(void **state) {
    whodata_event_node *first_node = calloc(1, sizeof(whodata_event_node));
    whodata_event_node *mid_node = calloc(1, sizeof(whodata_event_node));
    whodata_event_node *last_node = calloc(1, sizeof(whodata_event_node));

    if(!first_node || !mid_node || !last_node)
        return -1;

    if(first_node->id = strdup("first_node"), !first_node->id)
        return -1;

    if(mid_node->id = strdup("mid_node"), !mid_node->id)
        return -1;

    if(last_node->id = strdup("last_node"), !last_node->id)
        return -1;

    first_node->prev = NULL;
    first_node->next = mid_node;

    mid_node->prev = first_node;
    mid_node->next = last_node;

    last_node->prev = mid_node;
    last_node->next = NULL;

    syscheck.w_clist.first = first_node;
    syscheck.w_clist.last = last_node;

    syscheck.w_clist.current_size = 3;

    syscheck.w_clist.max_size = OS_SIZE_1024;
    syscheck.w_clist.max_remove = syscheck.w_clist.max_size * 10 * 0.01;
    syscheck.w_clist.alert_threshold = syscheck.w_clist.max_size * 80 * 0.01;

    return 0;
}

static int teardown_w_clist(void **state) {
    whodata_event_node *node;
    whodata_event_node *next;

    for(node = syscheck.w_clist.first; node; node = next) {
        next = node->next;

        if(node->id)
            free(node->id);

        free(node);
    }

    syscheck.w_clist.last = syscheck.w_clist.first = NULL;
    syscheck.w_clist.current_size = 0;
    syscheck.w_clist.max_size = 0;
    syscheck.w_clist.max_remove = 0;
    syscheck.w_clist.alert_threshold = 0;
    syscheck.w_clist.alerted = 0;

    return 0;
}

static int teardown_reset_errno(void **state) {
    errno = 0;
    return 0;
}

static int setup_state_checker(void **state) {
    // Remove everything from the syscheck struct
    Free_Syscheck(&syscheck);

    syscheck.opts = NULL;
    syscheck.scan_day = NULL;
    syscheck.scan_time = NULL;
    syscheck.ignore = NULL;
    syscheck.ignore_regex = NULL;
    syscheck.nodiff = NULL;
    syscheck.nodiff_regex = NULL;
    syscheck.dir = NULL;
    syscheck.filerestrict = NULL;
    syscheck.tag = NULL;
    syscheck.symbolic_links = NULL;
    syscheck.recursion_level = NULL;
    syscheck.registry_ignore = NULL;
    syscheck.registry_ignore_regex = NULL;
    syscheck.registry = NULL;
    syscheck.realtime = NULL;
    syscheck.prefilter_cmd = NULL;
    syscheck.audit_key = NULL;

    return 0;
}

static int teardown_state_checker(void **state) {
    int ret;

    // Remove everything that might have been added on the test
    Free_Syscheck(&syscheck);

    // Restore the syscheck struct
    expect_string(__wrap__mdebug1, formatted_msg, "(6287): Reading configuration file: 'test_syscheck.conf'");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node test_$");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node test_$ OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 1");
    expect_string(__wrap__mdebug1, formatted_msg, "(6208): Reading Client Configuration [test_syscheck.conf]");

    unit_testing = 0;
    ret = Read_Syscheck_Config("test_syscheck.conf");
    unit_testing = 1;

    return ret;
}

static int teardown_whodata_audit_start(void **state) {
    syscheck.wdata.directories = NULL;
    syscheck.wdata.fd = NULL;

    return 0;
}

static int setup_whodata_callback(void **state){
    OSHash_Add_ex_check_data = 0;
    return 0;
}

static int teardown_whodata_callback(void **state){
    OSHash_Add_ex_check_data = 1;
    return 0;
}

static int setup_win_whodata_evt(void **state) {
    whodata_evt *w_evt = calloc(1, sizeof(whodata_evt));

    if(!w_evt)
        return -1;

    if(w_evt->wnode = calloc(1, sizeof(whodata_event_node)), !w_evt->wnode)
        fail();

    *state = w_evt;

    return 0;
}

static int teardown_win_whodata_evt(void **state) {
    whodata_evt *w_evt = *state;

    whodata_clist_remove(w_evt->wnode);
    __real_free_whodata_event(w_evt);

    return 0;
}

static int setup_event_4663_dir(void **state) {
    if(setup_win_whodata_evt(state) != 0)
        return -1;

    if(setup_whodata_callback(state) != 0)
        return -1;

    return 0;
}

static int teardown_event_4663_dir(void **state) {
    if(teardown_win_whodata_evt(state) != 0)
        return -1;

    if(teardown_whodata_callback(state) != 0)
        return -1;

    return 0;
}


void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mterror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

char *__wrap_wstr_replace(const char * string, const char * search, const char * replace) {
    check_expected(string);
    check_expected(search);
    check_expected(replace);

    return mock_type(char*);
}

int __wrap_SendMSG(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc) {
    check_expected(message);
    check_expected(locmsg);
    check_expected(loc);

    return mock();
}

int __wrap_OSHash_Add_ex(OSHash *self, const char *key, void *data) {
    check_expected(self);
    check_expected(key);
    if (OSHash_Add_ex_check_data) {
        check_expected(data);
    }
    return mock();
}

void __wrap_free_whodata_event(whodata_evt *w_evt) {
    if (OSHash_Add_ex_check_data) {
        check_expected(w_evt);
    }
}

int __wrap_IsFile(const char * file)
{
    check_expected(file);
    return mock();
}

int __real_remove(const char *filename);
int __wrap_remove(const char *filename) {
    if(unit_testing){
        check_expected(filename);
        return mock();
    } else {
        return __real_remove(filename);
    }
}

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    check_expected(command);
    if (output) {
        *output = mock_type(char *);
    }
    *exitcode = mock_type(int);
    return mock();
}

FILE *__cdecl __real_fopen(const char * __restrict__ _Filename,const char * __restrict__ _Mode) __MINGW_ATTRIB_DEPRECATED_SEC_WARN;
FILE * __wrap_fopen(const char * __restrict__ _Filename,const char * __restrict__ _Mode) {
    if(unit_testing) {
        check_expected(_Filename);
        check_expected(_Mode);

        return mock_type(FILE*);
    } else {
        return __real_fopen(_Filename, _Mode);
    }
}

int __cdecl __real_fclose(FILE *_File);
int __wrap_fclose(FILE *_File) {
    if(unit_testing) {
        check_expected(_File);
        return mock();
    } else {
        return __real_fclose(_File);
    }
}

int __cdecl __real_atexit(void (__cdecl *callback)(void));
int __cdecl __wrap_atexit(void (__cdecl *callback)(void)) {
    if(unit_testing)
        return 0;
    else
        return __real_atexit(callback);
}

void *__wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    check_expected(self);
    check_expected(key);

    return mock_type(void*);
}

int __wrap_check_path_type(const char *dir) {
    check_expected(dir);

    return mock();
}

OSHash *__wrap_OSHash_Create() {
    function_called();
    return mock_type(OSHash*);
}

int __wrap_OSHash_SetFreeDataPointer(__attribute__((unused)) OSHash *self, __attribute__((unused)) void (free_data_function)(void *)) {
    function_called();
    return mock();
}

void __wrap_fim_whodata_event(whodata_evt * w_evt) {
    function_called();
}

int __wrap_fim_configuration_directory(const char *path, const char *entry) {
    function_called();
    check_expected(path);
    check_expected(entry);

    return mock();
}

void __wrap_fim_checker(char *path, fim_element *item, whodata_evt *w_evt, int report) {
    function_called();
    check_expected(w_evt);
    check_expected(report);
}

void *__wrap_OSHash_Get(const OSHash *self, const char *key) {
    check_expected(self);
    check_expected(key);

    return mock_type(void*);
}

char *__wrap_convert_windows_string(LPCWSTR string) {
    check_expected(string);
    return mock_type(char*);
}

void *__wrap_OSHash_Get_ex(const OSHash *self, const char *key) {
    check_expected(self);
    check_expected(key);

    return mock_type(void*);
}

/**************************************************************************/
/***************************set_winsacl************************************/
void test_set_winsacl_failed_opening(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 0);

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 500);
    expect_string(__wrap__merror, formatted_msg, "(6648): OpenProcessToken() failed. Error '500'.");

    set_winsacl(syscheck.dir[0], 0);
}

void test_set_winsacl_failed_privileges(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0); // Fail lookup privilege

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 500);
    expect_string(__wrap__merror, formatted_msg,  "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 500");

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 501);
    expect_string(__wrap__merror, formatted_msg,  "(6659): The privilege could not be activated. Error: '501'.");

    will_return(wrap_win_whodata_CloseHandle, 0);
    set_winsacl(syscheck.dir[0], 0);
}

void test_set_winsacl_failed_security_descriptor(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    // Increase privileges
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, -1);
    expect_string(__wrap__merror, formatted_msg, "(6650): GetNamedSecurityInfo() failed. Error '-1'");

    // Reduce Privilege
    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);
    expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");

    will_return(wrap_win_whodata_CloseHandle, 0);

    set_winsacl(syscheck.dir[0], 0);
}

void test_set_winsacl_no_need_to_configure_acl(void **state) {
    ACL old_sacl;
    ACCESS_ALLOWED_ACE ace;
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        everyone_sid = NULL;
        ev_sid_size = 1;

        // Set the ACL and ACE data
        ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
        ace.Mask = FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES | DELETE;

        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

        will_return(wrap_win_whodata_GetAce, &ace);
        will_return(wrap_win_whodata_GetAce, 1);

        will_return(wrap_win_whodata_EqualSid, 1);
    }

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 0);
}

void test_set_winsacl_unable_to_get_acl_info(void **state) {
    ACL old_sacl;
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 0);

    expect_string(__wrap__merror, formatted_msg, "(6651): The size of the 'C:\\a\\path' SACL could not be obtained.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_set_winsacl_fail_to_alloc_new_sacl(void **state) {
    ACL old_sacl;
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, NULL);

    expect_string(__wrap__merror, formatted_msg, "(6652): No memory could be reserved for the new SACL of 'C:\\a\\path'.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_set_winsacl_fail_to_initialize_new_sacl(void **state) {
    ACL old_sacl;
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 0);

    expect_string(__wrap__merror, formatted_msg, "(6653): The new SACL for 'C:\\a\\path' could not be created.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_set_winsacl_fail_getting_ace_from_old_sacl(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, NULL);
    will_return(wrap_win_whodata_GetAce, 0);

    expect_string(__wrap__merror, formatted_msg, "(6654): The ACE number 0 for 'C:\\a\\path' could not be obtained.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_set_winsacl_fail_adding_old_ace_into_new_sacl(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6655): The ACE number 0 of 'C:\\a\\path' could not be copied to the new ACL.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}
void test_set_winsacl_fail_to_alloc_new_ace(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, NULL);

    expect_string(__wrap__merror, formatted_msg,
        "(6656): No memory could be reserved for the new ACE of 'C:\\a\\path'.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_set_winsacl_fail_to_copy_sid(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SYSTEM_AUDIT_ACE ace;

    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 0);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
    assert_int_equal(ace.Header.AceType, SYSTEM_AUDIT_ACE_TYPE);
    assert_int_equal(ace.Header.AceFlags, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG);
    assert_int_equal(ace.Header.AceSize, 9);
    assert_int_equal(ace.Mask, DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES);
}

void test_set_winsacl_fail_to_add_ace(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SYSTEM_AUDIT_ACE ace;

    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 0);

    expect_string(__wrap__merror, formatted_msg, "(6657): The new ACE could not be added to 'C:\\a\\path'.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
    assert_int_equal(ace.Header.AceType, SYSTEM_AUDIT_ACE_TYPE);
    assert_int_equal(ace.Header.AceFlags, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG);
    assert_int_equal(ace.Header.AceSize, 9);
    assert_int_equal(ace.Mask, DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES);
}

void test_set_winsacl_fail_to_set_security_info(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SYSTEM_AUDIT_ACE ace;

    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 1234);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6658): SetNamedSecurityInfo() failed. Error: '5'.");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
    assert_int_equal(ace.Header.AceType, SYSTEM_AUDIT_ACE_TYPE);
    assert_int_equal(ace.Header.AceFlags, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG);
    assert_int_equal(ace.Header.AceSize, 9);
    assert_int_equal(ace.Mask, DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES);
}

void test_set_winsacl_success(void **state) {
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SYSTEM_AUDIT_ACE ace;

    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    int ret;

    ev_sid_size = 1;

    expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, 1234);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 1234);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = set_winsacl("C:\\a\\path", 0);

    assert_int_equal(ret, 0);
    assert_int_equal(ace.Header.AceType, SYSTEM_AUDIT_ACE_TYPE);
    assert_int_equal(ace.Header.AceFlags, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG);
    assert_int_equal(ace.Header.AceSize, 9);
    assert_int_equal(ace.Mask, DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES);
}

/**************************************************************************/

void test_set_privilege_lookup_error (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 0);

    assert_int_equal(ret, 1);
}

void test_set_privilege_adjust_token_error (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6634): AdjustTokenPrivileges() failed. Error: '5'");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 0);

    assert_int_equal(ret, 1);
}

void test_set_privilege_elevate_privilege (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 1);

    assert_int_equal(ret, 0);
}

void test_set_privilege_reduce_privilege (void **state) {
    int ret;

    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

    expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
    expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
    will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");

    ret = set_privilege((HANDLE)123456, "SeSecurityPrivilege", 0);

    assert_int_equal(ret, 0);
}

void test_w_update_sacl_AllocateAndInitializeSid_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6683): Could not obtain the sid of Everyone. Error '5'.");

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_OpenProcessToken_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) NULL);
    will_return(wrap_win_whodata_OpenProcessToken, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6684): OpenProcessToken() failed. Error '5'.");

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_add_privilege_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");
    }

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6685): The privilege could not be activated. Error: '5'.");

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_GetNamedSecurityInfo_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_FILE_NOT_FOUND);

    expect_string(__wrap__merror, formatted_msg, "(6686): GetNamedSecurityInfo() failed. Error '2'");

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_GetAclInformation_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 0);

    expect_string(__wrap__merror, formatted_msg, "(6687): The size of the 'C:\\a\\path' SACL could not be obtained.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_alloc_new_sacl_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, NULL);

    expect_string(__wrap__merror, formatted_msg, "(6688): No memory could be reserved for the new SACL of 'C:\\a\\path'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_InitializeAcl_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6689): The new SACL for 'C:\\a\\path' could not be created. Error: '5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_alloc_ace_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, NULL);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6690): No memory could be reserved for the new ACE of 'C:\\a\\path'. Error: '5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_CopySid_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL old_acl;
    SYSTEM_AUDIT_ACE ace;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, NULL);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6691): Could not copy the everyone SID for 'C:\\a\\path'. Error: '1-5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_old_sacl_GetAce_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, NULL);
    will_return(wrap_win_whodata_GetAce, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6692): The ACE number 0 for 'C:\\a\\path' could not be obtained.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_old_sacl_AddAce_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6693): The ACE number 0 of 'C:\\a\\path' could not be copied to the new ACL.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_new_sacl_AddAce_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(6694): The new ACE could not be added to 'C:\\a\\path'. Error: '5'.");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_SetNamedSecurityInfo_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 34567);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_PATH_NOT_FOUND);

    expect_string(__wrap__merror, formatted_msg,
        "(6695): SetNamedSecurityInfo() failed. Error: '3'");

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, OS_INVALID);
}

void test_w_update_sacl_remove_privilege_error(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 34567);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");
    }

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6685): The privilege could not be activated. Error: '5'.");

    /* Retry set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, 0);
}

void test_w_update_sacl_success(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEM_AUDIT_ACE ace;
    ACL old_acl;
    ACL_SIZE_INFORMATION old_sacl_info = {
        .AceCount = 1,
    };

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR) 2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
    will_return(wrap_win_whodata_GetAclInformation, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 13);
    will_return(wrap_win_whodata_win_alloc, (LPVOID) 34567);

    expect_value(wrap_win_whodata_InitializeAcl, pAcl, (LPVOID) 34567);
    expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 13);
    expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
    will_return(wrap_win_whodata_InitializeAcl, 1);

    expect_value(wrap_win_whodata_win_alloc, size, 9);
    will_return(wrap_win_whodata_win_alloc, &ace);

    will_return(wrap_win_whodata_CopySid, 1);

    will_return(wrap_win_whodata_GetAce, &old_sacl_info);
    will_return(wrap_win_whodata_GetAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_value(wrap_win_whodata_AddAce, pAcl, 34567);
    will_return(wrap_win_whodata_AddAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 34567);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

    /* goto end */
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = w_update_sacl("C:\\a\\path");

    assert_int_equal(ret, 0);
}

void test_whodata_check_arch_open_registry_key_error(void **state) {
    int ret;

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, NULL);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(1758): Unable to open registry key: 'System\\CurrentControlSet\\Control\\Session Manager\\Environment'.");

    ret = whodata_check_arch();

    assert_int_equal(ret, OS_INVALID);
}

void test_whodata_check_arch_query_key_value_error(void **state) {
    int ret;
    HKEY key;

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_OUTOFMEMORY);

    expect_string(__wrap__merror, formatted_msg,
        "(6682): Error reading 'Architecture' from Windows registry. (Error 14)");

    ret = whodata_check_arch();

    assert_int_equal(ret, OS_INVALID);
}

void test_whodata_check_arch_not_supported_arch(void **state) {
    int ret;
    HKEY key;
    const BYTE data[64] = "N/A";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

    ret = whodata_check_arch();

    assert_int_equal(ret, OS_INVALID);
}

void test_whodata_check_arch_x86(void **state) {
    int ret;
    HKEY key;
    const BYTE data[64] = "x86";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

    ret = whodata_check_arch();

    assert_int_equal(ret, 0);
    assert_int_equal(sys_64, 0);
}

void test_whodata_check_arch_amd64(void **state) {
    int ret;
    HKEY key;
    const BYTE data[64] = "AMD64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

    ret = whodata_check_arch();

    assert_int_equal(ret, 0);
    assert_int_equal(sys_64, 1);
}

void test_whodata_check_arch_ia64(void **state) {
    int ret;
    HKEY key;
    const BYTE data[64] = "IA64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

    ret = whodata_check_arch();

    assert_int_equal(ret, 0);
    assert_int_equal(sys_64, 1);
}

void test_whodata_check_arch_arm64(void **state) {
    int ret;
    HKEY key;
    const BYTE data[64] = "ARM64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

    ret = whodata_check_arch();

    assert_int_equal(ret, 0);
    assert_int_equal(sys_64, 1);
}

void test_whodata_adapt_path_no_changes (void **state) {
    char *path = "C:\\a\\path\\not\\replaced";

    whodata_adapt_path(&path);

    assert_string_equal(path, "C:\\a\\path\\not\\replaced");
}

void test_whodata_adapt_path_convert_system32 (void **state) {
    char *path = strdup("C:\\windows\\system32\\test");

    expect_string(__wrap_wstr_replace, string, path);
    expect_string(__wrap_wstr_replace, search, ":\\windows\\system32");
    expect_string(__wrap_wstr_replace, replace, ":\\windows\\sysnative");
    will_return(__wrap_wstr_replace, "C:\\windows\\sysnative\\test");

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6307): Convert 'C:\\windows\\system32\\test' to 'C:\\windows\\sysnative\\test' to process the whodata event.");

    whodata_adapt_path(&path);

    assert_string_equal(path, "C:\\windows\\sysnative\\test");
}

void test_whodata_adapt_path_convert_syswow64 (void **state) {
    char *path = strdup("C:\\windows\\syswow64\\test");

    expect_string(__wrap_wstr_replace, string, path);
    expect_string(__wrap_wstr_replace, search, ":\\windows\\syswow64");
    expect_string(__wrap_wstr_replace, replace, ":\\windows\\system32");
    will_return(__wrap_wstr_replace, "C:\\windows\\system32\\test");

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6307): Convert 'C:\\windows\\syswow64\\test' to 'C:\\windows\\system32\\test' to process the whodata event.");

    whodata_adapt_path(&path);

    assert_string_equal(path, "C:\\windows\\system32\\test");
}

void test_whodata_path_filter_file_discarded(void **state) {
    char *path = "C:\\$recycle.bin\\test.file";
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6289): File 'C:\\$recycle.bin\\test.file' is in the recycle bin. It will be discarded.");

    ret = whodata_path_filter(&path);

    assert_int_equal(ret, 1);
}

void test_whodata_path_filter_64_bit_system(void **state) {
    char *path = strdup("C:\\windows\\system32\\test");
    int ret;

    sys_64 = 1;

    expect_string(__wrap_wstr_replace, string, path);
    expect_string(__wrap_wstr_replace, search, ":\\windows\\system32");
    expect_string(__wrap_wstr_replace, replace, ":\\windows\\sysnative");
    will_return(__wrap_wstr_replace, "C:\\windows\\sysnative\\test");

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6307): Convert 'C:\\windows\\system32\\test' to 'C:\\windows\\sysnative\\test' to process the whodata event.");

    ret = whodata_path_filter(&path);

    assert_int_equal(ret, 0);
    assert_string_equal(path, "C:\\windows\\sysnative\\test");
}

void test_whodata_path_filter_32_bit_system(void **state) {
    char *path = "C:\\windows\\system32\\test";
    int ret;

    sys_64 = 0;

    ret = whodata_path_filter(&path);

    assert_int_equal(ret, 0);
    assert_string_equal(path, "C:\\windows\\system32\\test");
}

void test_get_whodata_path_error_determining_buffer_size(void **state) {
    const char *win_path = "C:\\a\\path";
    char *ret;

    expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
    expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
    will_return(wrap_win_whodata_WideCharToMultiByte, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, "(6306): The path could not be processed in Whodata mode. Error: 5");

    ret = get_whodata_path((const short unsigned int *)win_path);

    assert_null(ret);
}

void test_get_whodata_path_error_copying_buffer(void **state) {
    const char *win_path = "C:\\a\\path";
    char *ret;

    expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
    expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
    will_return(wrap_win_whodata_WideCharToMultiByte, 10);

    expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
    expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
    will_return(wrap_win_whodata_WideCharToMultiByte, "");
    will_return(wrap_win_whodata_WideCharToMultiByte, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, "(6306): The path could not be processed in Whodata mode. Error: 5");

    ret = get_whodata_path((const short unsigned int *)win_path);

    assert_null(ret);
}

void test_get_whodata_path_success(void **state) {
    const char *win_path = "C:\\a\\path";
    char *ret;

    expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
    expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
    will_return(wrap_win_whodata_WideCharToMultiByte, 21);

    expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
    expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
    will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
    will_return(wrap_win_whodata_WideCharToMultiByte, 21);

    ret = get_whodata_path((const short unsigned int *)win_path);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret, "C:\\another\\path.file");
}

void test_is_valid_sacl_sid_error(void **state) {
    int ret = 0;
    PACL sacl = NULL;
    everyone_sid = NULL;

    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

    expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");

    ret = is_valid_sacl(sacl, 0);
    assert_int_equal(ret, 0);
}

void test_is_valid_sacl_sacl_not_found(void **state) {
    int ret = 0;
    PACL sacl = NULL;
    everyone_sid = NULL;

    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6267): No SACL found on target. A new one will be created.");

    ret = is_valid_sacl(sacl, 0);
    assert_int_equal(ret, 2);
}

void test_is_valid_sacl_ace_not_found(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    PACL new_sacl = NULL;
    unsigned long new_sacl_size;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    // Set the new ACL size
    new_sacl_size = sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(unsigned long);
    new_sacl = (PACL) win_alloc(new_sacl_size);
    InitializeAcl(new_sacl, new_sacl_size, ACL_REVISION);
    new_sacl->AceCount=1;

    will_return(wrap_win_whodata_GetAce, NULL);
    will_return(wrap_win_whodata_GetAce, 0);

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 800);
    expect_string(__wrap__merror, formatted_msg, "(6633): Could not extract the ACE information. Error: '800'.");

    ret = is_valid_sacl(new_sacl, 0);
    assert_int_equal(ret, 0);
}

void test_is_valid_sacl_not_valid(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    PACL new_sacl = NULL;
    unsigned long new_sacl_size;

    everyone_sid = NULL;
    ev_sid_size = 1;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    // Set the new ACL size
    new_sacl_size = sizeof(SYSTEM_AUDIT_ACE) + ev_sid_size - sizeof(unsigned long);
    new_sacl = (PACL) win_alloc(new_sacl_size);
    InitializeAcl(new_sacl, new_sacl_size, ACL_REVISION);
    new_sacl->AceCount=1;

    will_return(wrap_win_whodata_GetAce, &new_sacl);
    will_return(wrap_win_whodata_GetAce, 1);

    ret = is_valid_sacl(new_sacl, 1);
    assert_int_equal(ret, 0);
}

void test_is_valid_sacl_valid(void **state) {
    int ret;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    ACL new_sacl;
    ACCESS_ALLOWED_ACE ace;

    everyone_sid = NULL;
    ev_sid_size = 1;

    // Set the ACL and ACE data
    new_sacl.AceCount=1;
    ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
    ace.Mask = FILE_WRITE_DATA | WRITE_DAC | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;

    expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
    expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
    will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

    will_return(wrap_win_whodata_GetAce, &ace);
    will_return(wrap_win_whodata_GetAce, 1);

    will_return(wrap_win_whodata_EqualSid, 1);

    ret = is_valid_sacl(&new_sacl, 1);
    assert_int_equal(ret, 1);
}

void test_replace_device_path_invalid_path(void **state) {
    char *path = strdup("invalid\\path");

    replace_device_path(&path);

    *state = path;

    assert_string_equal(path, "invalid\\path");
}

void test_replace_device_path_empty_wdata_device(void **state) {
    char *path = strdup("\\C:\\a\\path");

    replace_device_path(&path);

    *state = path;

    assert_string_equal(path, "\\C:\\a\\path");
}

void test_replace_device_path_device_not_found(void **state) {
    char *path = strdup("\\Device\\NotFound0\\a\\path");
    syscheck.wdata.device[0] = strdup("\\Device\\HarddiskVolume1");
    syscheck.wdata.drive[0] = strdup("D:");
    syscheck.wdata.device[1] = strdup("\\Device\\Floppy0");
    syscheck.wdata.drive[1] = strdup("A:");

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6304): Find device '\\Device\\HarddiskVolume1' in path '\\Device\\NotFound0\\a\\path'");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6304): Find device '\\Device\\Floppy0' in path '\\Device\\NotFound0\\a\\path'");

    replace_device_path(&path);

    *state = path;

    assert_string_equal(path, "\\Device\\NotFound0\\a\\path");
}

void test_replace_device_path_device_found(void **state) {
    char *path = strdup("\\Device\\Floppy0\\a\\path");
    syscheck.wdata.device[0] = strdup("\\Device\\HarddiskVolume1");
    syscheck.wdata.drive[0] = strdup("D:");
    syscheck.wdata.device[1] = strdup("\\Device\\Floppy0");
    syscheck.wdata.drive[1] = strdup("A:");

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6304): Find device '\\Device\\HarddiskVolume1' in path '\\Device\\Floppy0\\a\\path'");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6304): Find device '\\Device\\Floppy0' in path '\\Device\\Floppy0\\a\\path'");
    expect_string(__wrap__mdebug2, formatted_msg,
        "(6305): Replacing '\\Device\\Floppy0\\a\\path' to 'A:\\a\\path'");

    replace_device_path(&path);

    *state = path;

    assert_string_equal(path, "A:\\a\\path");
}

void test_get_drive_names_access_denied_error(void **state) {
    wchar_t *volume_name = L"\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}";
    char *device = "C";

    expect_memory(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, lpszVolumeName, volume_name, wcslen(volume_name));
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, OS_MAXSTR);
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mwarn, formatted_msg, "GetVolumePathNamesForVolumeNameW (5)'Input/output error'");

    get_drive_names(volume_name, device);
}

void test_get_drive_names_more_data_error(void **state) {
    wchar_t *volume_name = L"\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}";
    char *device = "C";

    expect_string(wrap_win_whodata_GetVolumePathNamesForVolumeNameW,
        lpszVolumeName, L"\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}");

    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, OS_MAXSTR);
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_MORE_DATA);

    expect_memory(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, lpszVolumeName, volume_name, wcslen(volume_name));
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 1);
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, L"");
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mwarn, formatted_msg, "GetVolumePathNamesForVolumeNameW (5)'Input/output error'");

    get_drive_names(volume_name, device);
}

void test_get_drive_names_success(void **state) {
    wchar_t *volume_name = L"\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}";
    char *device = "C";
    wchar_t *volume_paths = L"A\0C\0\\Some\\path\0";

    expect_memory(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, lpszVolumeName, volume_name, wcslen(volume_name));

    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 16);
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, volume_paths);
    will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'A'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'C'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point '\\Some\\path'");


    get_drive_names(volume_name, device);
}

void test_get_volume_names_unable_to_find_first_volume(void **state) {
    int ret;
    will_return(wrap_win_whodata_FindFirstVolumeW, L"");
    will_return(wrap_win_whodata_FindFirstVolumeW, INVALID_HANDLE_VALUE);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mwarn, formatted_msg, "FindFirstVolumeW failed (5)'Input/output error'");

    expect_value(wrap_win_whodata_FindVolumeClose, hFindVolume, INVALID_HANDLE_VALUE);
    will_return(wrap_win_whodata_FindVolumeClose, 1);

    ret = get_volume_names();

    assert_int_equal(ret, -1);
}

void test_get_volume_names_bad_path(void **state) {
    int ret;
    will_return(wrap_win_whodata_FindFirstVolumeW, L"Not a valid volume");
    will_return(wrap_win_whodata_FindFirstVolumeW, (HANDLE)123456);

    expect_string(__wrap__mwarn, formatted_msg, "Find Volume returned a bad path: Not a valid volume");

    expect_value(wrap_win_whodata_FindVolumeClose, hFindVolume, (HANDLE)123456);
    will_return(wrap_win_whodata_FindVolumeClose, 1);

    ret = get_volume_names();

    assert_int_equal(ret, -1);
}

void test_get_volume_names_no_dos_device(void **state) {
    int ret;
    wchar_t *str = L"";
    will_return(wrap_win_whodata_FindFirstVolumeW, L"\\\\?\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}\\");
    will_return(wrap_win_whodata_FindFirstVolumeW, (HANDLE)123456);

    expect_string(wrap_win_whodata_QueryDosDeviceW, lpDeviceName, L"Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}");
    will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));
    will_return(wrap_win_whodata_QueryDosDeviceW, str);
    will_return(wrap_win_whodata_QueryDosDeviceW, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mwarn, formatted_msg, "QueryDosDeviceW failed (5)'Input/output error'");

    expect_value(wrap_win_whodata_FindVolumeClose, hFindVolume, (HANDLE)123456);
    will_return(wrap_win_whodata_FindVolumeClose, 1);

    ret = get_volume_names();

    assert_int_equal(ret, -1);
}

void test_get_volume_names_error_on_next_volume(void **state) {
    int ret;
    wchar_t *str = L"C:";
    wchar_t *volume_name = L"\\\\?\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}\\";

    will_return(wrap_win_whodata_FindFirstVolumeW, volume_name);
    will_return(wrap_win_whodata_FindFirstVolumeW, (HANDLE)123456);

    expect_string(wrap_win_whodata_QueryDosDeviceW, lpDeviceName, L"Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}");
    will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));
    will_return(wrap_win_whodata_QueryDosDeviceW, str);
    will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));

    // Inside get_drive_names
    {
        wchar_t *volume_paths = L"A\0C\0\\Some\\path\0";

        expect_memory(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, lpszVolumeName, volume_name, wcslen(volume_name));

        will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 16);
        will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, volume_paths);
        will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 1);

        expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'A'");
        expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'C'");
        expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point '\\Some\\path'");
    }

    expect_value(wrap_win_whodata_FindNextVolumeW, hFindVolume, (HANDLE)123456);
    will_return(wrap_win_whodata_FindNextVolumeW, L"");
    will_return(wrap_win_whodata_FindNextVolumeW, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mwarn, formatted_msg, "FindNextVolumeW failed (5)'Input/output error'");

    expect_value(wrap_win_whodata_FindVolumeClose, hFindVolume, (HANDLE)123456);
    will_return(wrap_win_whodata_FindVolumeClose, 1);

    ret = get_volume_names();

    assert_int_equal(ret, -1);
}

void test_get_volume_names_no_more_files(void **state) {
    int ret;
    wchar_t *str = L"C:";
    wchar_t *volume_name = L"\\\\?\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}\\";

    will_return(wrap_win_whodata_FindFirstVolumeW, volume_name);
    will_return(wrap_win_whodata_FindFirstVolumeW, (HANDLE)123456);

    expect_string(wrap_win_whodata_QueryDosDeviceW, lpDeviceName, L"Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}");
    will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));
    will_return(wrap_win_whodata_QueryDosDeviceW, str);
    will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));

    // Inside get_drive_names
    {
        wchar_t *volume_paths = L"A\0C\0\\Some\\path\0";

        expect_memory(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, lpszVolumeName, volume_name, wcslen(volume_name));

        will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 16);
        will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, volume_paths);
        will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 1);

        expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'A'");
        expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'C'");
        expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point '\\Some\\path'");
    }

    expect_value(wrap_win_whodata_FindNextVolumeW, hFindVolume, (HANDLE)123456);
    will_return(wrap_win_whodata_FindNextVolumeW, L"");
    will_return(wrap_win_whodata_FindNextVolumeW, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_NO_MORE_FILES);

    expect_value(wrap_win_whodata_FindVolumeClose, hFindVolume, (HANDLE)123456);
    will_return(wrap_win_whodata_FindVolumeClose, 1);

    ret = get_volume_names();

    assert_int_equal(ret, 0);
}

void test_notify_SACL_change(void **state) {
    expect_string(__wrap_SendMSG, message,
        "ossec: Audit: The SACL of 'C:\\a\\path' has been modified and can no longer be scanned in whodata mode.");
    expect_string(__wrap_SendMSG, locmsg, "syscheck");
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 0); // Return value is discarded

    notify_SACL_change("C:\\a\\path");
}

void test_whodata_hash_add_unable_to_add(void **state) {
    wchar_t *data = L"Some random data";
    int ret;

    expect_value(__wrap_OSHash_Add_ex, self, (OSHash*)123456);
    expect_string(__wrap_OSHash_Add_ex, key, "key");
    expect_memory(__wrap_OSHash_Add_ex, data, data, wcslen(data));
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6631): The event could not be added to the 'tag' hash table. Target: 'key'.");

    ret = whodata_hash_add((OSHash*)123456, "key", data, "tag");

    assert_int_equal(ret, 0);
}

void test_whodata_hash_add_duplicate_entry(void **state) {
    wchar_t *data = L"Some random data";
    int ret;

    expect_value(__wrap_OSHash_Add_ex, self, (OSHash*)123456);
    expect_string(__wrap_OSHash_Add_ex, key, "key");
    expect_memory(__wrap_OSHash_Add_ex, data, data, wcslen(data));
    will_return(__wrap_OSHash_Add_ex, 1);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6630): The event could not be added to the 'tag' hash table because it is duplicated. Target: 'key'.");

    ret = whodata_hash_add((OSHash*)123456, "key", data, "tag");

    assert_int_equal(ret, 1);
}

void test_whodata_hash_add_success(void **state) {
    wchar_t *data = L"Some random data";
    int ret;

    expect_value(__wrap_OSHash_Add_ex, self, (OSHash*)123456);
    expect_string(__wrap_OSHash_Add_ex, key, "key");
    expect_memory(__wrap_OSHash_Add_ex, data, data, wcslen(data));
    will_return(__wrap_OSHash_Add_ex, 2);

    ret = whodata_hash_add((OSHash*)123456, "key", data, "tag");

    assert_int_equal(ret, 2);
}
/*****************************restore_sacls********************************/
void test_restore_sacls_openprocesstoken_failed(void **state){
    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 0);

    will_return(wrap_win_whodata_GetLastError, (unsigned int) 500);

    expect_string(__wrap__merror, formatted_msg,
        "(6648): OpenProcessToken() failed. Error '500'.");

    will_return(wrap_win_whodata_CloseHandle, 0);
    will_return(wrap_win_whodata_CloseHandle, 0);

    restore_sacls();
}

void test_restore_sacls_set_privilege_failed(void **state){
    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // set_privilege
    expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);
    expect_string(__wrap__merror, formatted_msg, "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");
    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);
    expect_string(__wrap__merror, formatted_msg, "(6659): The privilege could not be activated. Error: '5'.");

    will_return(wrap_win_whodata_CloseHandle, 0);
    will_return(wrap_win_whodata_CloseHandle, 0);
    restore_sacls();
}

int setup_restore_sacls(void **state) {
    int *ptr = malloc(sizeof(int));

    if(ptr == NULL)
        return -1;

    *ptr = syscheck.wdata.dirs_status[0].status;

    *state = ptr;
    // Set realtime
    syscheck.wdata.dirs_status[0].status |= WD_IGNORE_REST;
    return 0;
}

int teardown_restore_sacls(void **state) {
    int *ptr = (int *)state;
    syscheck.wdata.dirs_status[0].status = *ptr;
    free(*state);
    return 0;
}

void test_restore_sacls_securityNameInfo_failed(void **state){
    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }
    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_FILE_NOT_FOUND);
    expect_string(__wrap__merror, formatted_msg, "(6650): GetNamedSecurityInfo() failed. Error '2'");

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);
    will_return(wrap_win_whodata_CloseHandle, 0);

    restore_sacls();
}

void test_restore_sacls_deleteAce_failed(void **state){
    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }
    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    ACL acl;
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    expect_value(wrap_win_whodata_DeleteAce, pAcl, &acl);
    expect_value(wrap_win_whodata_DeleteAce, dwAceIndex, 0);
    will_return(wrap_win_whodata_DeleteAce, 0);
    will_return(wrap_win_whodata_GetLastError, 500);
    expect_string(__wrap__merror, formatted_msg, "(6646): DeleteAce() failed restoring the SACLs. Error '500'");
    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);
    will_return(wrap_win_whodata_CloseHandle, 0);

    restore_sacls();
}

void test_restore_sacls_SetNamedSecurityInfo_failed(void **state){
    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }
    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    ACL acl;
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    expect_value(wrap_win_whodata_DeleteAce, pAcl, &acl);
    expect_value(wrap_win_whodata_DeleteAce, dwAceIndex, 0);
    will_return(wrap_win_whodata_DeleteAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, &acl);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_PATH_NOT_FOUND);
    expect_string(__wrap__merror, formatted_msg, "(6658): SetNamedSecurityInfo() failed. Error: '3'.");

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);
    will_return(wrap_win_whodata_CloseHandle, 0);

    restore_sacls();
}

void test_restore_sacls_success(void **state){
    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }
    // GetNamedSecurity
    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    ACL acl;
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    expect_value(wrap_win_whodata_DeleteAce, pAcl, &acl);
    expect_value(wrap_win_whodata_DeleteAce, dwAceIndex, 0);
    will_return(wrap_win_whodata_DeleteAce, 1);

    expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
    expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, &acl);
    will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_RESTORED, syscheck.dir[0]);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    /* Inside set_privilege */
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);
    will_return(wrap_win_whodata_CloseHandle, 0);

    restore_sacls();
}
/***********************************restore_audit_policies***********************************/
void test_restore_audit_policies_backup_not_found(void **state) {
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, -1);
    expect_string(__wrap__merror, formatted_msg, "(6622): There is no backup of audit policies. Policies will not be restored.");

    int ret = restore_audit_policies();
    assert_int_equal(ret, 1);
}

void test_restore_audit_policies_command_failed(void **state) {
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, -1);
    will_return(__wrap_wm_exec, -1);

    expect_string(__wrap__merror, formatted_msg, "(6635): Auditpol backup error: 'failed to execute command'.");

    int ret = restore_audit_policies();
    assert_int_equal(ret, 1);
}

void test_restore_audit_policies_command2_failed(void **state) {
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, -1);
    will_return(__wrap_wm_exec, 1);

    expect_string(__wrap__merror, formatted_msg, "(6635): Auditpol backup error: 'time overtaken while running the command'.");

    int ret = restore_audit_policies();
    assert_int_equal(ret, 1);
}

void test_restore_audit_policies_command3_failed(void **state) {
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, -1);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__merror, formatted_msg, "(6635): Auditpol backup error: 'command returned failure'. Output: 'OUTPUT COMMAND'.");

    int ret = restore_audit_policies();
    assert_int_equal(ret, 1);
}

void test_restore_audit_policies_success(void **state) {
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, "OUTPUT COMMAND");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    int ret = restore_audit_policies();
    assert_int_equal(ret, 0);
}
/****************************************audit_restore**************************************/
void test_audit_restore(void **state) {
    // restore_sacls
    {
        expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
        will_return(wrap_win_whodata_OpenProcessToken, (HANDLE) 123456);
        will_return(wrap_win_whodata_OpenProcessToken, 1);

        // set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
        }
        // GetNamedSecurity
        expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
        ACL acl;
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

        expect_value(wrap_win_whodata_DeleteAce, pAcl, &acl);
        expect_value(wrap_win_whodata_DeleteAce, dwAceIndex, 0);
        will_return(wrap_win_whodata_DeleteAce, 1);

        expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, syscheck.dir[0]);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, &acl);
        will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

        char debug_msg[OS_MAXSTR];
        snprintf(debug_msg, OS_MAXSTR, FIM_SACL_RESTORED, syscheck.dir[0]);
        expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

        /* Inside set_privilege */
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
        }

        will_return(wrap_win_whodata_CloseHandle, 0);
        will_return(wrap_win_whodata_CloseHandle, 0);
    }

    // restore_audit_policies
    {
        expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
        will_return(__wrap_IsFile, 0);

        expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\backup-policies\"");
        will_return(__wrap_wm_exec, "OUTPUT COMMAND");
        will_return(__wrap_wm_exec, 0);
        will_return(__wrap_wm_exec, 0);
    }

    restore_policies = 1;
    audit_restore();

}
/********************************************************************************************/
/****************************************whodata_callback**************************************/
void test_whodata_callback_EvtRenderFailed(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event = NULL;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeNull; // Wrong buffer type
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    will_return(wrap_win_whodata_GetLastError, 500);
    expect_string(__wrap__merror, formatted_msg, "(6623): Error rendering the event. Error 500.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_invalid_rendered_params(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event = NULL;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeNull; // Wrong buffer type
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_string(__wrap__merror, formatted_msg, "(6624): Invalid number of rendered parameters.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_invalid_parameter_event_id(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event = NULL;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeNull; // Wrong buffer type
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_string(__wrap__merror, formatted_msg, "(6681): Invalid parameter type (0) for 'event_id'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_invalid_parameter_path(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event = NULL;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = 0; //Wrong event_id
    buffer[2].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_string(__wrap__merror, formatted_msg, "(6681): Invalid parameter type (0) for 'path'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_get_whodata_path_error(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event = NULL;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = 0; //Wrong event_id
    buffer[2].Type = EvtVarTypeString;
    buffer[2].XmlVal = L"C:\\a\\path";
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    // Inside get_whodata_path
    {
        expect_memory(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\a\\path", wcslen(L"C:\\a\\path"));
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__mdebug1, formatted_msg, "(6306): The path could not be processed in Whodata mode. Error: 5");
    }

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_whodata_path_filter_error(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event = NULL;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = 0; //Wrong event_id
    buffer[2].Type = EvtVarTypeString;
    buffer[2].XmlVal = L"C:\\$recycle.bin\\test.file";
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    // Inside get_whodata_path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\$recycle.bin\\test.file");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 27);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\$recycle.bin\\test.file");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\$recycle.bin\\test.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 27);
    }

    // Inside whodata_path_filter
    {
        expect_string(__wrap__mdebug2, formatted_msg,
            "(6289): File 'c:\\$recycle.bin\\test.file' is in the recycle bin. It will be discarded.");
    }

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_invalid_parameter_mask(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeNull;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeNull;
    buffer[4].Type = EvtVarTypeSizeT;
    buffer[5].Type = EvtVarTypeSizeT;
    buffer[6].Type = EvtVarTypeNull;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\a\\path";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[0].Int16Val = 0;
    buffer[4].SizeTVal = 0;
    buffer[5].SizeTVal = 0;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_name'.");
    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'process_name'.");
    expect_string(__wrap__merror, formatted_msg, "(6681): Invalid parameter type (0) for 'mask'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_invalid_user_id(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = 0;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"user_name";
    buffer[2].Type = EvtVarTypeString;
    buffer[2].XmlVal = L"C:\\a\\path";
    buffer[3].Type = EvtVarTypeNull;
    buffer[4].Type = EvtVarTypeSizeT;
    buffer[4].SizeTVal = 0;
    buffer[5].Type = EvtVarTypeSizeT;
    buffer[5].SizeTVal = 0;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeSid;
    buffer[7].SidVal = NULL;    //  Ignored by wrapper
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_memory(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\a\\path", wcslen(L"C:\\a\\path"));
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_memory(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\a\\path", wcslen(L"C:\\a\\path"));
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"user_name", wcslen(L"user_name"));
    will_return(__wrap_convert_windows_string, strdup("user_name"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'process_name'.");

    will_return(wrap_win_whodata_ConvertSidToStringSid, NULL);
    will_return(wrap_win_whodata_ConvertSidToStringSid, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(6246): Invalid identifier for user 'user_name'");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_unknown_user_id(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = 0;
    buffer[1].Type = EvtVarTypeNull;
    buffer[2].Type = EvtVarTypeString;
    buffer[2].XmlVal = L"C:\\a\\path";
    buffer[3].Type = EvtVarTypeNull;
    buffer[4].Type = EvtVarTypeSizeT;
    buffer[4].SizeTVal = 0;
    buffer[5].Type = EvtVarTypeSizeT;
    buffer[5].SizeTVal = 0;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeSid;
    buffer[7].SidVal = NULL;    //  Ignored by wrapper
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_memory(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\a\\path", wcslen(L"C:\\a\\path"));
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_memory(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, L"C:\\a\\path", wcslen(L"C:\\a\\path"));
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_name'.");
    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'process_name'.");

    will_return(wrap_win_whodata_ConvertSidToStringSid, NULL);
    will_return(wrap_win_whodata_ConvertSidToStringSid, 0);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_WHODATA_INVALID_UNKNOWN_UID);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_path(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[2].Type = EvtVarTypeString;
    buffer[1].Type = EvtVarTypeNull;
    buffer[3].Type = EvtVarTypeNull;
    buffer[4].Type = EvtVarTypeNull;
    buffer[5].Type = EvtVarTypeNull;
    buffer[6].Type = EvtVarTypeNull;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\a\\path";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_name'.");
    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'process_name'.");
    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'process_id'.");
    expect_string(__wrap__merror, formatted_msg, "(6681): Invalid parameter type (0) for 'handle_id'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_wrong_id(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 0;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");
    expect_string(__wrap__merror, formatted_msg, "(6628): Invalid EventID. The whodata cannot be extracted.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4656_not_active(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4656;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = DELETE;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\another\\path.file");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6239): 'c:\\another\\path.file' is discarded because its monitoring is not activated.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4656_canceled(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = syscheck.dir[1];
    buffer[0].Int16Val = 4656;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = DELETE;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, syscheck.dir[1]);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, syscheck.dir[1]);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, syscheck.dir[1]);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\windows");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 8);

    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, "(6240): The monitoring of '%s' in whodata mode has been canceled. Added to the ignore list.", syscheck.dir[1]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4656_handler_not_removed(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    syscheck.wdata.dirs_status[1].status = WD_CHECK_WHODATA;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    char win_path[OS_MAXSTR] = {0};
    strcat(win_path, syscheck.dir[2]);
    strcat(win_path, "\\sasa.exe");
    buffer[0].Int16Val = 4656;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 0;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, win_path);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, win_path);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, win_path);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\windows\\sysnative\\");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 1);

    expect_string(__wrap_check_path_type, dir, "c:\\windows\\sysnative\\");
    will_return(__wrap_check_path_type, 0);

    // OSHash_Add_ex
    {
        expect_value(__wrap_OSHash_Add_ex, self, syscheck.wdata.fd);
        expect_string(__wrap_OSHash_Add_ex, key, "1234567890123456789");
        will_return(__wrap_OSHash_Add_ex, 1);
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6235): Real-time Whodata events queue for Windows is full. Removing the first '0'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '0' events have been deleted from the whodata list.");

    expect_string(__wrap__mdebug1, formatted_msg, "(6229): The handler ('1234567890123456789') will be updated.");
    expect_string(__wrap__mdebug2, formatted_msg, "(6630): The event could not be added to the 'whodata' hash table because it is duplicated. Target: '1234567890123456789'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)NULL);

    expect_string(__wrap__merror, formatted_msg, "(6626): The handler '1234567890123456789' could not be removed from the whodata hash table.");
    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4656_directory(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    syscheck.wdata.dirs_status[8].status = WD_CHECK_WHODATA;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    EVT_VARIANT buffer[NUM_EVENTS];
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0";
    buffer[0].Int16Val = 4656;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, win_path);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, strlen(win_path));

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, win_path);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, win_path);
        will_return(wrap_win_whodata_WideCharToMultiByte, strlen(win_path));
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\windows\\system32\\windowspowershell\\v1.0");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 8);

    expect_string(__wrap_check_path_type, dir, "c:\\windows\\system32\\windowspowershell\\v1.0");
    will_return(__wrap_check_path_type, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "(6235): Real-time Whodata events queue for Windows is full. Removing the first '0'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '0' events have been deleted from the whodata list.");

    // OSHash_Add_ex
    {
        wchar_t *data = L"Some random data";
        expect_value(__wrap_OSHash_Add_ex, self, syscheck.wdata.fd);
        expect_string(__wrap_OSHash_Add_ex, key, "1234567890123456789");
        will_return(__wrap_OSHash_Add_ex, 2);
    }

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4656_directory_failed(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    syscheck.wdata.dirs_status[8].status = WD_CHECK_WHODATA;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    EVT_VARIANT buffer[NUM_EVENTS];
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0";
    buffer[0].Int16Val = 4656;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, win_path);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, strlen(win_path));

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, win_path);
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, win_path);
        will_return(wrap_win_whodata_WideCharToMultiByte, strlen(win_path));
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\windows\\system32\\windowspowershell\\v1.0");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 8);

    expect_string(__wrap_check_path_type, dir, "c:\\windows\\system32\\windowspowershell\\v1.0");
    will_return(__wrap_check_path_type, 2);

    expect_string(__wrap__mdebug1, formatted_msg, "(6235): Real-time Whodata events queue for Windows is full. Removing the first '0'");
    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '0' events have been deleted from the whodata list.");

    // OSHash_Add_ex
    {
        expect_value(__wrap_OSHash_Add_ex, self, syscheck.wdata.fd);
        expect_string(__wrap_OSHash_Add_ex, key, "1234567890123456789");
        will_return(__wrap_OSHash_Add_ex, 0);
    }

    expect_string(__wrap__merror, formatted_msg, "(6631): The event could not be added to the 'whodata' hash table. Target: '1234567890123456789'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4660_deleted_file(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4660;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);
    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    whodata_evt w_evt;
    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, &w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4660_not_deleted(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4660;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, NULL);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4658_no_event_to_delete(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)NULL);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4658_file_deleted(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->ignore_remove_event = 1;
    w_evt->scan_directory = (char)0;
    w_evt->deleted = 1;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_function_call(__wrap_fim_whodata_event);

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
    assert_int_equal(w_evt->ignore_remove_event, 0);
}

void test_whodata_callback_event_4658_file_moved_or_renamed(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->ignore_remove_event = 1;
    w_evt->scan_directory = (char)0;
    w_evt->deleted = 0;
    w_evt->mask = DELETE;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_function_call(__wrap_fim_whodata_event);

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
    assert_int_equal(w_evt->ignore_remove_event, 0);
}

void test_whodata_callback_event_4658_file_not_modified(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->ignore_remove_event = 1;
    w_evt->scan_directory = (char)0;
    w_evt->deleted = 0;
    w_evt->mask = 0;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_function_call(__wrap_fim_whodata_event);

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
    assert_int_equal(w_evt->ignore_remove_event, 1);
}

void test_whodata_callback_event_4658_trigger_directory_scan(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->scan_directory = (char)1;
    w_evt->mask = DELETE;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_function_call(__wrap_fim_whodata_event);

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4658_rename_dir(void **state) {

    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    everyone_sid = NULL;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->scan_directory = (char)1;
    w_evt->mask = FILE_APPEND_DATA;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "C:\\a\\path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_function_call(__wrap_fim_checker);
    expect_value(__wrap_fim_checker, w_evt, w_evt);
    expect_value(__wrap_fim_checker, report, 1);

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4658_new_file_added(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;
    SYSTEMTIME st;


    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    memset(&st, 0, sizeof(SYSTEMTIME));
    st.wYear = 2020;
    st.wMonth = 3;
    st.wDay = 3;

    w_evt->scan_directory = (char)1;
    w_evt->mask = FILE_WRITE_DATA;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get, key, "C:\\a\\path");
    will_return(__wrap_OSHash_Get, &w_dir);

    will_return(wrap_win_whodata_GetSystemTime, &st);

    expect_function_call(__wrap_fim_whodata_event);

    expect_string(__wrap__mdebug1, formatted_msg,
        "(6231): The 'C:\\a\\path' directory has been scanned after detecting event of new files.");

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4658_no_new_files(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->scan_directory = (char)1;
    w_evt->mask = 0;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6245): The 'C:\\a\\path' directory has not been scanned because no new files have been detected. Mask: '0'");

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4658_scan_aborted(void **state) {
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    if(w_evt->path = strdup("C:\\a\\path"), !w_evt->path)
        fail();

    w_evt->scan_directory = (char)2;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[0].Int16Val = (INT16)4658;
    buffer[1].Type = EvtVarTypeString;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].Type = EvtVarTypeUInt16;
    buffer[2].Int16Val = (INT16)0;
    buffer[3].Type = EvtVarTypeString;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[4].UInt64Val = 4;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[6].UInt32Val = 6;
    buffer[7].Type = EvtVarTypeNull;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "1234567890123456789");
    will_return(__wrap_OSHash_Delete_ex, w_evt);

    expect_string(__wrap__mdebug1, formatted_msg,
       "(6232): Scanning of the 'C:\\a\\path' directory is aborted because something has gone wrong.");

    expect_value(__wrap_free_whodata_event, w_evt, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4663_invalid_param(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    w_evt->scan_directory = (char)2;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 0); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 0);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, &w_dir);

    expect_string(__wrap__merror, formatted_msg, "(6681): Invalid parameter type (0) for 'event_time'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4663_wrong_event_time_param(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeNull;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    buffer[8].FileTimeVal = 72623859790382856;

    w_evt->scan_directory = (char)2;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, &w_dir);

    expect_string(__wrap__merror, formatted_msg, "(6681): Invalid parameter type (0) for 'event_time'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4663_file_time_error(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeFileTime;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    buffer[8].FileTimeVal = 72623859790382856;

    w_evt->scan_directory = (char)2;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    /* get_file_time */
    {
        SYSTEMTIME systime;
        FILETIME ftime;

        memset(&systime, 0, sizeof(SYSTEMTIME));
        memset(&ftime, 0, sizeof(FILETIME));

        ftime.dwHighDateTime = 0x01020304;
        ftime.dwLowDateTime = 0x05060708;

        systime.wYear = 2020;
        systime.wMonth = 3;
        systime.wDay = 10;
        systime.wHour = 12;
        systime.wMinute = 55;
        systime.wSecond = 32;

        expect_memory(wrap_win_whodata_FileTimeToSystemTime, lpFileTime, &ftime, sizeof(FILETIME));
        will_return(wrap_win_whodata_FileTimeToSystemTime, &systime);
        will_return(wrap_win_whodata_FileTimeToSystemTime, 0);
    }

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, &w_dir);

    expect_string(__wrap__merror, formatted_msg, "(6627): Could not get the time of the event whose handler is '1234567890123456789'.");
    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 1);
}

void test_whodata_callback_event_4663_timestamp_ok(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeFileTime;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    buffer[8].FileTimeVal = 72623859790382856;

    w_evt->scan_directory = (char)3;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    /* get_file_time */
    {
        SYSTEMTIME systime;
        FILETIME ftime;

        memset(&systime, 0, sizeof(SYSTEMTIME));
        memset(&ftime, 0, sizeof(FILETIME));

        ftime.dwHighDateTime = 0x01020304;
        ftime.dwLowDateTime = 0x05060708;

        systime.wYear = 2020;
        systime.wMonth = 3;
        systime.wDay = 10;
        systime.wHour = 12;
        systime.wMinute = 55;
        systime.wSecond = 32;

        expect_memory(wrap_win_whodata_FileTimeToSystemTime, lpFileTime, &ftime, sizeof(FILETIME));
        will_return(wrap_win_whodata_FileTimeToSystemTime, &systime);
        will_return(wrap_win_whodata_FileTimeToSystemTime, 1);
    }

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, &w_dir);

    expect_string(__wrap__mdebug2, formatted_msg, "(6241): The 'c:\\another\\path.file' directory has been scanned. It does not need to do it again.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4663_no_event(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeFileTime;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;
    buffer[8].FileTimeVal = 72623859790382856;

    w_evt->scan_directory = (char)2;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\another\\path.file");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6243): The 'c:\\another\\path.file' directory has been discarded because it is not being monitored in whodata mode.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4663_no_dir(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;
    w_evt->scan_directory = (char)2;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeFileTime;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\another\\path.file");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    // OSHash_Add_ex
    {
        expect_value(__wrap_OSHash_Add_ex, self, syscheck.wdata.directories);
        expect_string(__wrap_OSHash_Add_ex, key, "c:\\another\\path.file");
        will_return(__wrap_OSHash_Add_ex, 1);
    }

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6630): The event could not be added to the 'directories' hash table because it is duplicated. Target: 'c:\\another\\path.file'.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}


void test_whodata_callback_event_4663_dir(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;
    w_evt->scan_directory = (char)2;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeFileTime;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = 6;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.wdata.directories);
    expect_string(__wrap_OSHash_Get_ex, key, "c:\\another\\path.file");
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_function_call(__wrap_fim_configuration_directory);
    expect_string(__wrap_fim_configuration_directory, path, "c:\\another\\path.file");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    OSHash_Add_ex_check_data = 0;
    // OSHash_Add_ex
    {
        expect_value(__wrap_OSHash_Add_ex, self, syscheck.wdata.directories);
        expect_string(__wrap_OSHash_Add_ex, key, "c:\\another\\path.file");
        will_return(__wrap_OSHash_Add_ex, 2);
    }

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6244): New files have been detected in the 'c:\\another\\path.file' directory and will be scanned.");

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

void test_whodata_callback_event_4663_dir_removed(void **state){
    EVT_SUBSCRIBE_NOTIFY_ACTION action = EvtSubscribeActionDeliver;
    EVT_HANDLE event;
    const int NUM_EVENTS = 10;
    const int SIZE_EVENTS = sizeof(EVT_VARIANT) * NUM_EVENTS;
    EVT_VARIANT buffer[NUM_EVENTS];
    whodata_evt *w_evt = *state;
    whodata_directory w_dir;

    /* EvtRender first call */
    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, 0); // BufferSize
    will_return(wrap_win_whodata_EvtRender, NULL); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS); // BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    /* EvtRender second call */
    memset(buffer, 0, SIZE_EVENTS);
    buffer[0].Type = EvtVarTypeUInt16; // Correct buffer type
    buffer[1].Type = EvtVarTypeString;
    buffer[2].Type = EvtVarTypeString;
    buffer[3].Type = EvtVarTypeString;
    buffer[4].Type = EvtVarTypeHexInt64;
    buffer[5].Type = EvtVarTypeHexInt64;
    buffer[6].Type = EvtVarTypeHexInt32;
    buffer[7].Type = EvtVarTypeNull;
    buffer[8].Type = EvtVarTypeFileTime;
    const char* win_path = "C:\\a\\path";
    buffer[0].Int16Val = 4663;
    buffer[1].XmlVal = L"USERNAME";
    buffer[2].XmlVal = (const short unsigned int *) win_path;
    buffer[3].XmlVal = L"PROCESS_NAME";
    buffer[4].UInt64Val = 4;
    buffer[5].UInt64Val = 1234567890123456789;
    buffer[6].UInt32Val = DELETE;

    expect_value(wrap_win_whodata_EvtRender, Context, context);
    expect_value(wrap_win_whodata_EvtRender, Fragment, event);
    expect_value(wrap_win_whodata_EvtRender, Flags, EvtRenderEventValues);
    expect_value(wrap_win_whodata_EvtRender, BufferSize, SIZE_EVENTS); // BufferSize
    will_return(wrap_win_whodata_EvtRender, buffer); // Buffer
    will_return(wrap_win_whodata_EvtRender, SIZE_EVENTS);// BufferUsed
    will_return(wrap_win_whodata_EvtRender, 9); // PropertyCount
    will_return(wrap_win_whodata_EvtRender, 1);

    //Whodata path
    {
        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);

        expect_string(wrap_win_whodata_WideCharToMultiByte, lpWideCharStr, "C:\\a\\path");
        expect_value(wrap_win_whodata_WideCharToMultiByte, cchWideChar, -1);
        will_return(wrap_win_whodata_WideCharToMultiByte, "C:\\another\\path.file");
        will_return(wrap_win_whodata_WideCharToMultiByte, 21);
    }

    expect_memory(__wrap_convert_windows_string, string, L"USERNAME", wcslen(L"USERNAME"));
    will_return(__wrap_convert_windows_string, strdup("USERNAME"));

    expect_memory(__wrap_convert_windows_string, string, L"PROCESS_NAME", wcslen(L"PROCESS_NAME"));
    will_return(__wrap_convert_windows_string, strdup("PROCESS_NAME"));

    expect_string(__wrap__mwarn, formatted_msg, "(6681): Invalid parameter type (0) for 'user_id'.");

    expect_value(__wrap_OSHash_Get, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Get, key, "1234567890123456789");
    will_return(__wrap_OSHash_Get, w_evt);

    int ret = whodata_callback(action, NULL, event);
    assert_int_equal(ret, 0);
}

/********************************************************************************************/
void test_check_object_sacl_open_process_error(void **state) {
    int ret;

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)NULL);
    will_return(wrap_win_whodata_OpenProcessToken, 0);

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6648): OpenProcessToken() failed. Error '5'.");

    ret = check_object_sacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_check_object_sacl_unable_to_set_privilege(void **state) {
    int ret;

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

        expect_string(__wrap__merror, formatted_msg,
            "(6647): Could not find the 'SeSecurityPrivilege' privilege. Error: 5");
    }

    will_return(wrap_win_whodata_GetLastError, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg, "(6659): The privilege could not be activated. Error: '5'.");

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = check_object_sacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_check_object_sacl_unable_to_retrieve_security_info(void **state) {
    int ret;

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, NULL);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_FILE_NOT_FOUND);

    expect_string(__wrap__merror, formatted_msg, "(6650): GetNamedSecurityInfo() failed. Error '2'");

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = check_object_sacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_check_object_sacl_invalid_sacl(void **state) {
    ACL acl;
    int ret;

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // is_valid_sacl
    {
        SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

        expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
    }

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = check_object_sacl("C:\\a\\path", 0);

    assert_int_equal(ret, 1);
}

void test_check_object_sacl_valid_sacl(void **state) {
    ACL acl;
    int ret;

    expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
    will_return(wrap_win_whodata_OpenProcessToken, 1);

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
    }

    expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
    expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
    will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

    // Inside is_valid_sacl
    {
        SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
        ACCESS_ALLOWED_ACE ace;

        everyone_sid = NULL;
        ev_sid_size = 1;

        // Set the ACL and ACE data
        ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
        ace.Mask = FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES | DELETE;

        expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
        expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
        will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

        will_return(wrap_win_whodata_GetAce, &ace);
        will_return(wrap_win_whodata_GetAce, 1);

        will_return(wrap_win_whodata_EqualSid, 1);
    }

    // Inside set_privilege
    {
        expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
        will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
        will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

        expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
        expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
        will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

        expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
    }

    will_return(wrap_win_whodata_CloseHandle, 0);

    ret = check_object_sacl("C:\\a\\path", 0);

    assert_int_equal(ret, 0);
}

void test_whodata_clist_remove_single_node(void **state) {
    whodata_clist_remove(syscheck.w_clist.first);

    assert_null(syscheck.w_clist.first);
    assert_null(syscheck.w_clist.last);
    assert_int_equal(syscheck.w_clist.current_size, 0);
}

void test_whodata_clist_remove_first_node(void **state) {
    whodata_clist_remove(syscheck.w_clist.first);

    assert_non_null(syscheck.w_clist.first);
    assert_non_null(syscheck.w_clist.last);
    assert_string_equal(syscheck.w_clist.first->id, "mid_node");
    assert_ptr_equal(syscheck.w_clist.first->next, syscheck.w_clist.last);
    assert_null(syscheck.w_clist.first->prev);
    assert_string_equal(syscheck.w_clist.last->id, "last_node");
    assert_ptr_equal(syscheck.w_clist.last->prev, syscheck.w_clist.first);
    assert_null(syscheck.w_clist.last->next);
    assert_int_equal(syscheck.w_clist.current_size, 2);
}

void test_whodata_clist_remove_last_node(void **state) {
    whodata_clist_remove(syscheck.w_clist.last);

    assert_non_null(syscheck.w_clist.first);
    assert_non_null(syscheck.w_clist.last);
    assert_string_equal(syscheck.w_clist.first->id, "first_node");
    assert_ptr_equal(syscheck.w_clist.first->next, syscheck.w_clist.last);
    assert_null(syscheck.w_clist.first->prev);
    assert_string_equal(syscheck.w_clist.last->id, "mid_node");
    assert_ptr_equal(syscheck.w_clist.last->prev, syscheck.w_clist.first);
    assert_null(syscheck.w_clist.last->next);
    assert_int_equal(syscheck.w_clist.current_size, 2);
}

void test_whodata_clist_remove_center_node(void **state) {
    whodata_clist_remove(syscheck.w_clist.first->next);

    assert_non_null(syscheck.w_clist.first);
    assert_non_null(syscheck.w_clist.last);
    assert_string_equal(syscheck.w_clist.first->id, "first_node");
    assert_ptr_equal(syscheck.w_clist.first->next, syscheck.w_clist.last);
    assert_null(syscheck.w_clist.first->prev);
    assert_string_equal(syscheck.w_clist.last->id, "last_node");
    assert_ptr_equal(syscheck.w_clist.last->prev, syscheck.w_clist.first);
    assert_null(syscheck.w_clist.last->next);
    assert_int_equal(syscheck.w_clist.current_size, 2);
}

void test_free_win_whodata_evt(void **state) {
    whodata_evt evt;

    evt.wnode = syscheck.w_clist.first->next;

    expect_value(__wrap_free_whodata_event, w_evt, &evt);

    free_win_whodata_evt(&evt);

    assert_non_null(syscheck.w_clist.first);
    assert_non_null(syscheck.w_clist.last);
    assert_string_equal(syscheck.w_clist.first->id, "first_node");
    assert_ptr_equal(syscheck.w_clist.first->next, syscheck.w_clist.last);
    assert_null(syscheck.w_clist.first->prev);
    assert_string_equal(syscheck.w_clist.last->id, "last_node");
    assert_ptr_equal(syscheck.w_clist.last->prev, syscheck.w_clist.first);
    assert_null(syscheck.w_clist.last->next);
    assert_int_equal(syscheck.w_clist.current_size, 2);
}

void test_free_win_whodata_evt_null_event(void **state) {
    // Nothing to check on this condition
    free_win_whodata_evt(NULL);
}

void test_compare_timestamp_t1_year_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2019;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 0);
}

void test_compare_timestamp_t2_year_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2019;
    t2.wYear = 2020;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

void test_compare_timestamp_t1_month_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 3;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 0);
}

void test_compare_timestamp_t2_month_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 3;
    t2.wMonth = 5;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

void test_compare_timestamp_t1_day_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 10;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 0);
}

void test_compare_timestamp_t2_day_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 10;
    t2.wDay = 15;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

void test_compare_timestamp_t1_hour_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 14;
    t2.wHour = 12;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 0);
}

void test_compare_timestamp_t2_hour_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 12;
    t2.wHour = 14;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

void test_compare_timestamp_t1_minute_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 14;
    t2.wHour = 14;

    t1.wMinute = 30;
    t2.wMinute = 25;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 0);
}

void test_compare_timestamp_t2_minute_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 14;
    t2.wHour = 14;

    t1.wMinute = 25;
    t2.wMinute = 30;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

void test_compare_timestamp_t1_seconds_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 14;
    t2.wHour = 14;

    t1.wMinute = 30;
    t2.wMinute = 30;

    t1.wSecond = 30;
    t2.wSecond = 25;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 0);
}

void test_compare_timestamp_t2_seconds_bigger(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 14;
    t2.wHour = 14;

    t1.wMinute = 30;
    t2.wMinute = 30;

    t1.wSecond = 25;
    t2.wSecond = 30;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

void test_compare_timestamp_equal_dates(void **state) {
    SYSTEMTIME t1, t2;
    int ret;

    memset(&t1, 0, sizeof(SYSTEMTIME));
    memset(&t2, 0, sizeof(SYSTEMTIME));

    t1.wYear = 2020;
    t2.wYear = 2020;

    t1.wMonth = 5;
    t2.wMonth = 5;

    t1.wDay = 15;
    t2.wDay = 15;

    t1.wHour = 14;
    t2.wHour = 14;

    t1.wMinute = 30;
    t2.wMinute = 30;

    t1.wSecond = 30;
    t2.wSecond = 30;

    ret = compare_timestamp(&t1, &t2);

    assert_int_equal(ret, 1);
}

/* run_whodata_scan */

void test_run_whodata_scan_invalid_arch(void **state) {
    int ret;
/* whodata_check_arch() */
{
    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, NULL);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_ACCESS_DENIED);

    expect_string(__wrap__merror, formatted_msg,
        "(1758): Unable to open registry key: 'System\\CurrentControlSet\\Control\\Session Manager\\Environment'.");
}
    ret = run_whodata_scan();
    assert_int_equal(ret, 1);
}

void test_run_whodata_scan_no_audit_policies(void **state) {
    int ret;

/* Inside whodata_check_arch */
{
    HKEY key;
    const BYTE data[64] = "ARM64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

}

/* Inside set_policies */
{
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);
    expect_string(__wrap_remove, filename, "tmp\\backup-policies");
    will_return(__wrap_remove, 1);

    expect_string(__wrap__merror, formatted_msg,
         "(6660): 'tmp\\backup-policies' could not be removed: 'No such file or directory' (2).");
}

    expect_string(__wrap__merror, formatted_msg,
         "(6916): Local audit policies could not be configured.");

    ret = run_whodata_scan();
    assert_int_equal(ret, 1);
}

void test_run_whodata_scan_no_auto_audit_policies(void **state) {
    int ret;

/* Inside whodata_check_arch */
{
    HKEY key;
    const BYTE data[64] = "ARM64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

}

/* Inside set_policies */
{
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);
    expect_string(__wrap_remove, filename, "tmp\\backup-policies");
    will_return(__wrap_remove, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__merror, formatted_msg,
        "(6915): Audit policies could not be auto-configured due to the Windows version. Check if they are correct for whodata mode.");
}

    expect_string(__wrap__merror, formatted_msg, "(6916): Local audit policies could not be configured.");

    ret = run_whodata_scan();
    assert_int_equal(ret, 1);
}

void test_run_whodata_scan_error_event_channel(void **state) {
    int ret;

/* Inside whodata_check_arch */
{
    HKEY key;
    const BYTE data[64] = "ARM64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

}

/* Inside set_policies */
{
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap_fopen, _Filename, "tmp\\backup-policies");
    expect_string(__wrap_fopen, _Mode, "r");
    will_return(__wrap_fopen, (FILE*)1234);

    expect_string(__wrap_fopen, _Filename, "tmp\\new-policies");
    expect_string(__wrap_fopen, _Mode, "w");
    will_return(__wrap_fopen, (FILE*)2345);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, "some policies");

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, "some policies");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, NULL);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\new-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 0);
}

    DWORD fields_number = 9;
    EVT_HANDLE event;

    expect_value(wrap_win_whodata_EvtCreateRenderContext, ValuePathsCount, fields_number);
    expect_value(wrap_win_whodata_EvtCreateRenderContext, ValuePaths, event_fields);
    expect_value(wrap_win_whodata_EvtCreateRenderContext, Flags, EvtRenderContextValues);
    will_return(wrap_win_whodata_EvtCreateRenderContext, event);

    wchar_t *query = L"Event[ System[band(Keywords, 9007199254740992)] and "
                            "( ( ( EventData/Data[@Name='ObjectType'] = 'File' ) and "
                            "( (  System/EventID = 4656 or System/EventID = 4663 ) and "
                            "( EventData[band(Data[@Name='AccessMask'], 327938‬)] ) ) ) or "
                            "System/EventID = 4658 or System/EventID = 4660 ) ]";

    expect_value(wrap_win_whodata_EvtSubscribe, Session, NULL);
    expect_value(wrap_win_whodata_EvtSubscribe, SignalEvent, NULL);
    expect_string(wrap_win_whodata_EvtSubscribe, ChannelPath, L"Security");
    expect_string(wrap_win_whodata_EvtSubscribe, Query, query);
    expect_value(wrap_win_whodata_EvtSubscribe, Bookmark, NULL);
    expect_value(wrap_win_whodata_EvtSubscribe, Context, NULL);
    expect_value(wrap_win_whodata_EvtSubscribe, Callback, (EVT_SUBSCRIBE_CALLBACK)whodata_callback);
    expect_value(wrap_win_whodata_EvtSubscribe, Flags, EvtSubscribeToFutureEvents);

    will_return(wrap_win_whodata_EvtSubscribe, NULL);

    expect_string(__wrap__merror, formatted_msg, "(6621): Event Channel subscription could not be made. Whodata scan is disabled.");

    ret = run_whodata_scan();
    assert_int_equal(ret, 1);
}

void test_run_whodata_scan_success(void **state) {
    int ret;

/* Inside whodata_check_arch */
{
    HKEY key;
    const BYTE data[64] = "ARM64";

    expect_value(wrap_win_whodata_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_win_whodata_RegOpenKeyEx, lpSubKey,
        "System\\CurrentControlSet\\Control\\Session Manager\\Environment");
    expect_value(wrap_win_whodata_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_win_whodata_RegOpenKeyEx, samDesired, KEY_READ);
    will_return(wrap_win_whodata_RegOpenKeyEx, &key);
    will_return(wrap_win_whodata_RegOpenKeyEx, ERROR_SUCCESS);

    expect_string(wrap_win_whodata_RegQueryValueEx, lpValueName, "PROCESSOR_ARCHITECTURE");
    expect_value(wrap_win_whodata_RegQueryValueEx, lpReserved, NULL);
    expect_value(wrap_win_whodata_RegQueryValueEx, lpType, NULL);
    will_return(wrap_win_whodata_RegQueryValueEx, data);
    will_return(wrap_win_whodata_RegQueryValueEx, ERROR_SUCCESS);

}

/* Inside set_policies */
{
    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap_fopen, _Filename, "tmp\\backup-policies");
    expect_string(__wrap_fopen, _Mode, "r");
    will_return(__wrap_fopen, (FILE*)1234);

    expect_string(__wrap_fopen, _Filename, "tmp\\new-policies");
    expect_string(__wrap_fopen, _Mode, "w");
    will_return(__wrap_fopen, (FILE*)2345);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, "some policies");

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, "some policies");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, NULL);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\new-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 0);
}

    DWORD fields_number = 9;
    EVT_HANDLE event;

    expect_value(wrap_win_whodata_EvtCreateRenderContext, ValuePathsCount, fields_number);
    expect_value(wrap_win_whodata_EvtCreateRenderContext, ValuePaths, event_fields);
    expect_value(wrap_win_whodata_EvtCreateRenderContext, Flags, EvtRenderContextValues);
    will_return(wrap_win_whodata_EvtCreateRenderContext, event);

    wchar_t *query = L"Event[ System[band(Keywords, 9007199254740992)] and "
                            "( ( ( EventData/Data[@Name='ObjectType'] = 'File' ) and "
                            "( (  System/EventID = 4656 or System/EventID = 4663 ) and "
                            "( EventData[band(Data[@Name='AccessMask'], 327938‬)] ) ) ) or "
                            "System/EventID = 4658 or System/EventID = 4660 ) ]";

    expect_value(wrap_win_whodata_EvtSubscribe, Session, NULL);
    expect_value(wrap_win_whodata_EvtSubscribe, SignalEvent, NULL);
    expect_string(wrap_win_whodata_EvtSubscribe, ChannelPath, L"Security");
    expect_string(wrap_win_whodata_EvtSubscribe, Query, query);
    expect_value(wrap_win_whodata_EvtSubscribe, Bookmark, NULL);
    expect_value(wrap_win_whodata_EvtSubscribe, Context, NULL);
    expect_value(wrap_win_whodata_EvtSubscribe, Callback, (EVT_SUBSCRIBE_CALLBACK)whodata_callback);
    expect_value(wrap_win_whodata_EvtSubscribe, Flags, EvtSubscribeToFutureEvents);

    will_return(wrap_win_whodata_EvtSubscribe, 1);

    expect_string(__wrap__minfo, formatted_msg, "(6019): File integrity monitoring real-time Whodata engine started.");

    ret = run_whodata_scan();
    assert_int_equal(ret, 0);
}

void test_get_file_time_error(void **state) {
    unsigned long long file_time_val = 0x0102030405060708;
    SYSTEMTIME time, returned_time;
    FILETIME ftime;
    int ret;

    memset(&time, 0, sizeof(SYSTEMTIME));
    memset(&returned_time, 0, sizeof(SYSTEMTIME));

    ftime.dwHighDateTime = 0x01020304;
    ftime.dwLowDateTime = 0x05060708;

    expect_memory(wrap_win_whodata_FileTimeToSystemTime, lpFileTime, &ftime, sizeof(FILETIME));
    will_return(wrap_win_whodata_FileTimeToSystemTime, &returned_time);
    will_return(wrap_win_whodata_FileTimeToSystemTime, 0);

    ret = get_file_time(file_time_val, &time);

    assert_int_equal(ret, 0);
}

void test_get_file_time_success(void **state) {
    unsigned long long file_time_val = 0x0102030405060708;
    SYSTEMTIME time, returned_time;
    FILETIME ftime;
    int ret;

    memset(&time, 0, sizeof(SYSTEMTIME));
    memset(&returned_time, 0, sizeof(SYSTEMTIME));

    ftime.dwHighDateTime = 0x01020304;
    ftime.dwLowDateTime = 0x05060708;

    returned_time.wYear = 2020;
    returned_time.wMonth = 3;
    returned_time.wDay = 10;
    returned_time.wHour = 12;
    returned_time.wMinute = 55;
    returned_time.wSecond = 32;

    expect_memory(wrap_win_whodata_FileTimeToSystemTime, lpFileTime, &ftime, sizeof(FILETIME));
    will_return(wrap_win_whodata_FileTimeToSystemTime, &returned_time);
    will_return(wrap_win_whodata_FileTimeToSystemTime, 1);

    ret = get_file_time(file_time_val, &time);

    assert_int_equal(ret, 1);
    assert_memory_equal(&time, &returned_time, sizeof(SYSTEMTIME));
}

void test_set_subscription_query(void **state) {
    wchar_t output[OS_MAXSTR];
    wchar_t *expected_output = L"Event[ System[band(Keywords, 9007199254740992)] and "
                                "( ( ( EventData/Data[@Name='ObjectType'] = 'File' ) and "
                                "( (  System/EventID = 4656 or System/EventID = 4663 ) and "
                                "( EventData[band(Data[@Name='AccessMask'], 327938‬)] ) ) ) or "
                                "System/EventID = 4658 or System/EventID = 4660 ) ]";

    set_subscription_query(output);

    assert_memory_equal(output, expected_output, wcslen(expected_output));
}

void test_set_policies_unable_to_remove_backup_file(void **state) {
    int ret;

    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 0);

    expect_string(__wrap_remove, filename, "tmp\\backup-policies");
    will_return(__wrap_remove, -1);
    errno = EACCES;

    expect_string(__wrap__merror, formatted_msg,
        "(6660): 'tmp\\backup-policies' could not be removed: 'Permission denied' (13).");

    ret = set_policies();

    assert_int_equal(ret, 1);
}

void test_set_policies_fail_getting_policies(void **state) {
    int ret;

    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__merror, formatted_msg,
    "(6915): Audit policies could not be auto-configured due to the Windows version. Check if they are correct for whodata mode.");

    ret = set_policies();

    assert_int_equal(ret, 2);
}

void test_set_policies_unable_to_open_backup_file(void **state) {
    int ret;

    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap_fopen, _Filename, "tmp\\backup-policies");
    expect_string(__wrap_fopen, _Mode, "r");
    will_return(__wrap_fopen, NULL);
    errno = EACCES;

    expect_string(__wrap__merror, formatted_msg,
        "(6661): 'tmp\\backup-policies' could not be opened: 'Permission denied' (13).");

    ret = set_policies();

    assert_int_equal(ret, 1);
}

void test_set_policies_unable_to_open_new_file(void **state) {
    int ret;

    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap_fopen, _Filename, "tmp\\backup-policies");
    expect_string(__wrap_fopen, _Mode, "r");
    will_return(__wrap_fopen, (FILE*)1234);

    expect_string(__wrap_fopen, _Filename, "tmp\\new-policies");
    expect_string(__wrap_fopen, _Mode, "w");
    will_return(__wrap_fopen, NULL);
    errno = EACCES;

    expect_string(__wrap__merror, formatted_msg,
        "(6661): 'tmp\\new-policies' could not be opened: 'Permission denied' (13).");

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 0);

    ret = set_policies();

    assert_int_equal(ret, 1);
}

void test_set_policies_unable_to_restore_policies(void **state) {
    int ret;

    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap_fopen, _Filename, "tmp\\backup-policies");
    expect_string(__wrap_fopen, _Mode, "r");
    will_return(__wrap_fopen, (FILE*)1234);

    expect_string(__wrap_fopen, _Filename, "tmp\\new-policies");
    expect_string(__wrap_fopen, _Mode, "w");
    will_return(__wrap_fopen, (FILE*)2345);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, "some policies");

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, "some policies");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, NULL);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\new-policies\"");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);
    expect_string(__wrap__merror, formatted_msg,
        "(6915): Audit policies could not be auto-configured due to the Windows version. Check if they are correct for whodata mode.");

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 0);

    ret = set_policies();

    assert_int_equal(ret, 2);
}
void test_set_policies_success(void **state) {
    int ret;

    expect_string(__wrap_IsFile, file, "tmp\\backup-policies");
    will_return(__wrap_IsFile, 1);

    expect_string(__wrap_wm_exec, command, "auditpol /backup /file:\"tmp\\backup-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap_fopen, _Filename, "tmp\\backup-policies");
    expect_string(__wrap_fopen, _Mode, "r");
    will_return(__wrap_fopen, (FILE*)1234);

    expect_string(__wrap_fopen, _Filename, "tmp\\new-policies");
    expect_string(__wrap_fopen, _Mode, "w");
    will_return(__wrap_fopen, (FILE*)2345);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, "some policies");

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, "some policies");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fgets, __stream, (FILE*)1234);
    will_return(wrap_win_whodata_fgets, NULL);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(wrap_win_whodata_fprintf, __stream, 2345);
    expect_string(wrap_win_whodata_fprintf, formatted_msg, ",System,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,1\n");
    will_return(wrap_win_whodata_fprintf, 0);

    expect_value(__wrap_fclose, _File, (FILE*)2345);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap_wm_exec, command, "auditpol /restore /file:\"tmp\\new-policies\"");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_value(__wrap_fclose, _File, (FILE*)1234);
    will_return(__wrap_fclose, 0);

    ret = set_policies();

    assert_int_equal(ret, 0);
}

void test_whodata_list_set_values(void **state) {
    // Clear the values to be checked
    syscheck.w_clist.max_size = 0;
    syscheck.w_clist.max_remove = 0;
    syscheck.w_clist.alert_threshold = 0;

    expect_string(__wrap__mdebug1, formatted_msg,
        "(6237): Whodata event queue values for Windows -> max_size:'1024' | max_remove:'102' | alert_threshold:'819'");

    whodata_list_set_values();

    assert_int_equal(syscheck.w_clist.max_size, 1024);
    assert_int_equal(syscheck.w_clist.max_remove, 102);
    assert_int_equal(syscheck.w_clist.alert_threshold, 819);
}

void test_whodata_list_remove_multiple_remove_none(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '0' events have been deleted from the whodata list.");

    whodata_list_remove_multiple(0);

    assert_int_equal(syscheck.w_clist.current_size, 3);
    assert_string_equal(syscheck.w_clist.first->id, "first_node");
    assert_string_equal(syscheck.w_clist.last->id, "last_node");
    assert_ptr_equal(syscheck.w_clist.first->next, syscheck.w_clist.last->prev);
    assert_null(syscheck.w_clist.first->prev);
    assert_null(syscheck.w_clist.last->next);
}

void test_whodata_list_remove_multiple_remove_one(void **state) {
    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "first_node");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)1234);

    expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)1234);

    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '1' events have been deleted from the whodata list.");

    whodata_list_remove_multiple(1);

    assert_int_equal(syscheck.w_clist.current_size, 2);
    assert_string_equal(syscheck.w_clist.first->id, "mid_node");
    assert_string_equal(syscheck.w_clist.last->id, "last_node");
    assert_ptr_equal(syscheck.w_clist.first->next, syscheck.w_clist.last);
    assert_ptr_equal(syscheck.w_clist.last->prev, syscheck.w_clist.first);
    assert_null(syscheck.w_clist.first->prev);
    assert_null(syscheck.w_clist.last->next);
}

void test_whodata_list_remove_multiple_remove_two(void **state) {
    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "first_node");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)1234);

    expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)1234);

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "mid_node");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)2345);

    expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)2345);

    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '2' events have been deleted from the whodata list.");

    whodata_list_remove_multiple(2);

    assert_int_equal(syscheck.w_clist.current_size, 1);
    assert_string_equal(syscheck.w_clist.first->id, "last_node");
    assert_string_equal(syscheck.w_clist.last->id, "last_node");
    assert_null(syscheck.w_clist.first->next);
    assert_null(syscheck.w_clist.last->prev);
    assert_null(syscheck.w_clist.first->prev);
    assert_null(syscheck.w_clist.last->next);
}

void test_whodata_list_remove_multiple_remove_more_than_available(void **state) {
    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "first_node");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)1234);

    expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)1234);

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "mid_node");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)2345);

    expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)2345);

    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
    expect_string(__wrap_OSHash_Delete_ex, key, "last_node");
    will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)3456);

    expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)3456);

    expect_string(__wrap__mdebug1, formatted_msg, "(6236): '3' events have been deleted from the whodata list.");

    whodata_list_remove_multiple(syscheck.w_clist.current_size * 10);

    assert_int_equal(syscheck.w_clist.current_size, 0);
    assert_null(syscheck.w_clist.first);
    assert_null(syscheck.w_clist.last);
}

void test_whodata_list_add_on_empty_list(void **state) {
    whodata_event_node *node;

    // setup some required values
    syscheck.w_clist.max_size = OS_SIZE_1024;
    syscheck.w_clist.max_remove = syscheck.w_clist.max_size * 0.1;
    syscheck.w_clist.alert_threshold = syscheck.w_clist.max_size * 80 * 0.01;

    node = whodata_list_add(strdup("A node"));

    assert_int_equal(syscheck.w_clist.current_size, 1);
    assert_non_null(node);
    assert_ptr_equal(node, syscheck.w_clist.first);
    assert_ptr_equal(node, syscheck.w_clist.last);
    assert_null(node->next);
    assert_null(node->prev);
    assert_string_equal(node->id, "A node");
}

void test_whodata_list_add_on_regular_list(void **state) {
    whodata_event_node *node;

    node = whodata_list_add(strdup("A node"));

    assert_int_equal(syscheck.w_clist.current_size, 4);
    assert_non_null(node);
    assert_ptr_not_equal(node, syscheck.w_clist.first);
    assert_ptr_equal(node, syscheck.w_clist.last);
    assert_null(node->next);
    assert_ptr_equal(node->prev, syscheck.w_clist.first->next->next);
    assert_string_equal(node->id, "A node");
}

void test_whodata_list_add_trigger_alert(void **state) {
    whodata_event_node *node;

    // Trick the list into thinking it is almost full
    syscheck.w_clist.current_size = syscheck.w_clist.alert_threshold + 1;

    expect_string(__wrap__mwarn, formatted_msg,
        "(6917): Real-time Whodata events queue for Windows has more than 819 elements.");

    node = whodata_list_add(strdup("A node"));

    assert_int_equal(syscheck.w_clist.current_size, 821);
    assert_non_null(node);
    assert_ptr_not_equal(node, syscheck.w_clist.first);
    assert_ptr_equal(node, syscheck.w_clist.last);
    assert_null(node->next);
    assert_ptr_equal(node->prev, syscheck.w_clist.first->next->next);
    assert_string_equal(node->id, "A node");
}

void test_whodata_list_add_on_full_list(void **state) {
    whodata_event_node *node;

    // Trick the list into thinking it is full
    syscheck.w_clist.current_size = syscheck.w_clist.max_size;

    expect_string(__wrap__mdebug1, formatted_msg,
        "(6235): Real-time Whodata events queue for Windows is full. Removing the first '102'");

    // Inside whodata_list_remove_multiple
    {
        expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
        expect_string(__wrap_OSHash_Delete_ex, key, "first_node");
        will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)1234);

        expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)1234);

        expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
        expect_string(__wrap_OSHash_Delete_ex, key, "mid_node");
        will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)2345);

        expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)2345);

        expect_value(__wrap_OSHash_Delete_ex, self, syscheck.wdata.fd);
        expect_string(__wrap_OSHash_Delete_ex, key, "last_node");
        will_return(__wrap_OSHash_Delete_ex, (whodata_evt *)3456);

        expect_value(__wrap_free_whodata_event, w_evt, (whodata_evt *)3456);

        expect_string(__wrap__mdebug1, formatted_msg, "(6236): '3' events have been deleted from the whodata list.");
    }

    node = whodata_list_add(strdup("A node"));

    assert_int_equal(syscheck.w_clist.current_size, 1022);
    assert_non_null(node);
    assert_ptr_equal(node, syscheck.w_clist.first);
    assert_ptr_equal(node, syscheck.w_clist.last);
    assert_null(node->next);
    assert_null(node->prev);
    assert_string_equal(node->id, "A node");
}

void test_state_checker_no_files_to_check(void **state) {
    int ret;
    void *input = NULL;

    if(syscheck.dir = calloc(1, sizeof(char*)), !syscheck.dir)
        fail();

    syscheck.dir[0] = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    ret = state_checker(input);

    assert_int_equal(ret, 0);
}

void test_state_checker_file_not_whodata(void **state) {
    int ret;
    void *input = NULL;

    if(syscheck.dir = calloc(2, sizeof(char*)), !syscheck.dir)
        fail();

    if(syscheck.dir[0] = strdup("C:\\a\\path"), !syscheck.dir[0])
        fail();

    // Leverage Free_Syscheck not free the wdata struct
    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    ret = state_checker(input);

    assert_int_equal(ret, 0);
}

void test_state_checker_file_does_not_exist(void **state) {
    int ret;
    void *input = NULL;
    SYSTEMTIME st;

    if(syscheck.dir = calloc(2, sizeof(char*)), !syscheck.dir)
        fail();

    if(syscheck.dir[0] = strdup("C:\\a\\path"), !syscheck.dir[0])
        fail();

    // Leverage Free_Syscheck not free the wdata struct
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_WHODATA | WD_STATUS_EXISTS;
    syscheck.wdata.dirs_status[0].object_type = WD_STATUS_DIR_TYPE;

    memset(&st, 0, sizeof(SYSTEMTIME));
    st.wYear = 2020;
    st.wMonth = 3;
    st.wDay = 3;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 0);

    expect_string(__wrap__mdebug1, formatted_msg,
        "(6022): 'C:\\a\\path' has been deleted. It will not be monitored in real-time Whodata mode.");

    will_return(wrap_win_whodata_GetSystemTime, &st);

    ret = state_checker(input);

    assert_int_equal(ret, 0);
    assert_memory_equal(&syscheck.wdata.dirs_status[0].last_check, &st, sizeof(SYSTEMTIME));
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_UNK_TYPE);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
}

void test_state_checker_file_with_invalid_sacl(void **state) {
    int ret;
    void *input = NULL;
    ACL acl;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};

    if(syscheck.dir = calloc(2, sizeof(char*)), !syscheck.dir)
        fail();

    if(syscheck.dir[0] = strdup("C:\\a\\path"), !syscheck.dir[0])
        fail();

    if(syscheck.opts = calloc(1, sizeof(int)), !syscheck.opts)
        fail();

    // Leverage Free_Syscheck not free the wdata struct
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_WHODATA | WD_STATUS_EXISTS;
    syscheck.wdata.dirs_status[0].object_type = WD_STATUS_DIR_TYPE;
    syscheck.opts[0] = (int)0xFFFFFFFF;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 1);

    // Inside check_object_sacl
    {
        expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
        will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
        will_return(wrap_win_whodata_OpenProcessToken, 1);

        // Inside set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
        }

        expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

        // is_valid_sacl
        {

            expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
            expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
            will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

            will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

            expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
        }

        // Inside set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
        }

        will_return(wrap_win_whodata_CloseHandle, 0);
    }

    expect_string(__wrap__minfo, formatted_msg,
        "(6021): The SACL of 'C:\\a\\path' has been modified and it is not valid for the real-time Whodata mode. Whodata will not be available for this file.");

    // Inside notify_SACL_change
    {
        expect_string(__wrap_SendMSG, message,
            "ossec: Audit: The SACL of 'C:\\a\\path' has been modified and can no longer be scanned in whodata mode.");
        expect_string(__wrap_SendMSG, locmsg, "syscheck");
        expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
        will_return(__wrap_SendMSG, 0); // Return value is discarded
    }

    ret = state_checker(input);

    assert_int_equal(ret, 0);
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_FILE_TYPE);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
    assert_null(syscheck.opts[0] & WHODATA_ACTIVE);
}

void test_state_checker_file_with_valid_sacl(void **state) {
    int ret;
    void *input = NULL;
    SYSTEMTIME st;
    ACL acl;

    if(syscheck.dir = calloc(2, sizeof(char*)), !syscheck.dir)
        fail();

    if(syscheck.dir[0] = strdup("C:\\a\\path"), !syscheck.dir[0])
        fail();

    if(syscheck.opts = calloc(1, sizeof(int)), !syscheck.opts)
        fail();

    // Leverage Free_Syscheck not free the wdata struct
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_WHODATA | WD_STATUS_EXISTS;
    syscheck.wdata.dirs_status[0].object_type = WD_STATUS_DIR_TYPE;
    syscheck.opts[0] = (int)0xFFFFFFFF;

    memset(&st, 0, sizeof(SYSTEMTIME));
    st.wYear = 2020;
    st.wMonth = 3;
    st.wDay = 3;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 1);

    // Inside check_object_sacl
    {
        expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
        will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
        will_return(wrap_win_whodata_OpenProcessToken, 1);

        // Inside set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
        }

        expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, &acl);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, (PSECURITY_DESCRIPTOR)2345);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

        // Inside is_valid_sacl
        {
            SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
            ACCESS_ALLOWED_ACE ace;

            everyone_sid = NULL;
            ev_sid_size = 1;

            // Set the ACL and ACE data
            ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
            ace.Mask = FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | FILE_WRITE_ATTRIBUTES | DELETE;

            expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
            expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
            will_return(wrap_win_whodata_AllocateAndInitializeSid, 1);

            will_return(wrap_win_whodata_GetAce, &ace);
            will_return(wrap_win_whodata_GetAce, 1);

            will_return(wrap_win_whodata_EqualSid, 1);
        }

        // Inside set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
        }

        will_return(wrap_win_whodata_CloseHandle, 0);
    }

    will_return(wrap_win_whodata_GetSystemTime, &st);

    ret = state_checker(input);

    assert_int_equal(ret, 0);
    assert_memory_equal(&syscheck.wdata.dirs_status[0].last_check, &st, sizeof(SYSTEMTIME));
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_FILE_TYPE);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
    assert_non_null(syscheck.opts[0] & WHODATA_ACTIVE);
}

void test_state_checker_dir_readded_error(void **state) {
    int ret;
    void *input = NULL;
    char debug_msg[OS_MAXSTR];

    if(syscheck.dir = calloc(2, sizeof(char*)), !syscheck.dir)
        fail();

    if(syscheck.dir[0] = strdup("C:\\a\\path"), !syscheck.dir[0])
        fail();

    if(syscheck.opts = calloc(1, sizeof(int)), !syscheck.opts)
        fail();

    // Leverage Free_Syscheck not free the wdata struct
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status &= ~WD_STATUS_EXISTS;
    syscheck.wdata.dirs_status[0].object_type = WD_STATUS_UNK_TYPE;
    syscheck.opts[0] = (int)0xFFFFFFFF;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 1);

    expect_string(__wrap__minfo, formatted_msg,
        "(6020): 'C:\\a\\path' has been re-added. It will be monitored in real-time Whodata mode.");

    // Inside set_winsacl
    {
        snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
        expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

        expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
        will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
        will_return(wrap_win_whodata_OpenProcessToken, 0);

        will_return(wrap_win_whodata_GetLastError, (unsigned int) 500);
        expect_string(__wrap__merror, formatted_msg, "(6648): OpenProcessToken() failed. Error '500'.");
    }

    expect_string(__wrap__merror, formatted_msg,
        "(6619): Unable to add directory to whodata real time monitoring: 'C:\\a\\path'. It will be monitored in Realtime");

    ret = state_checker(input);

    assert_int_equal(ret, 0);
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_FILE_TYPE);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
    assert_non_null(syscheck.opts[0] & REALTIME_ACTIVE);
}

void test_state_checker_dir_readded_succesful(void **state) {
    int ret;
    void *input = NULL;
    ACL old_sacl;
    ACL_SIZE_INFORMATION old_sacl_info = {.AceCount = 1};
    SYSTEM_AUDIT_ACE ace;
    SECURITY_DESCRIPTOR security_descriptor;
    SID_IDENTIFIER_AUTHORITY world_auth = {SECURITY_WORLD_SID_AUTHORITY};
    SYSTEMTIME st;

    if(syscheck.dir = calloc(2, sizeof(char*)), !syscheck.dir)
        fail();

    if(syscheck.dir[0] = strdup("C:\\a\\path"), !syscheck.dir[0])
        fail();

    if(syscheck.opts = calloc(1, sizeof(int)), !syscheck.opts)
        fail();

    // Leverage Free_Syscheck not free the wdata struct
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status &= ~WD_STATUS_EXISTS;
    syscheck.wdata.dirs_status[0].object_type = WD_STATUS_UNK_TYPE;
    syscheck.opts[0] = (int)0xFFFFFFFF;

    memset(&st, 0, sizeof(SYSTEMTIME));
    st.wYear = 2020;
    st.wMonth = 3;
    st.wDay = 3;

    expect_string(__wrap__mdebug1, formatted_msg, "(6233): Checking thread set to '300' seconds.");

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    expect_value(wrap_win_whodata_Sleep, dwMilliseconds, WDATA_DEFAULT_INTERVAL_SCAN * 1000);

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 1);

    expect_string(__wrap__minfo, formatted_msg,
        "(6020): 'C:\\a\\path' has been re-added. It will be monitored in real-time Whodata mode.");

    // Inside set_winsacl
    {
        ev_sid_size = 1;

        expect_string(__wrap__mdebug2, formatted_msg, "(6266): The SACL of 'C:\\a\\path' will be configured.");

        expect_value(wrap_win_whodata_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
        will_return(wrap_win_whodata_OpenProcessToken, (HANDLE)123456);
        will_return(wrap_win_whodata_OpenProcessToken, 1);

        // Inside set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6268): The 'SeSecurityPrivilege' privilege has been added.");
        }

        // GetNamedSecurity
        expect_string(wrap_win_whodata_GetNamedSecurityInfo, pObjectName, "C:\\a\\path");
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
        expect_value(wrap_win_whodata_GetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, &old_sacl);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, &security_descriptor);
        will_return(wrap_win_whodata_GetNamedSecurityInfo, ERROR_SUCCESS);

        // Inside is_valid_sacl
        {
            expect_memory(wrap_win_whodata_AllocateAndInitializeSid, pIdentifierAuthority, &world_auth, 6);
            expect_value(wrap_win_whodata_AllocateAndInitializeSid, nSubAuthorityCount, 1);
            will_return(wrap_win_whodata_AllocateAndInitializeSid, 0);

            will_return(wrap_win_whodata_GetLastError, (unsigned int) 700);

            expect_string(__wrap__merror, formatted_msg, "(6632): Could not obtain the sid of Everyone. Error '700'.");
        }

        expect_string(__wrap__mdebug1, formatted_msg, "(6263): Setting up SACL for 'C:\\a\\path'");

        will_return(wrap_win_whodata_GetAclInformation, &old_sacl_info);
        will_return(wrap_win_whodata_GetAclInformation, 1);

        expect_value(wrap_win_whodata_win_alloc, size, 9);
        will_return(wrap_win_whodata_win_alloc, 1234);

        expect_value(wrap_win_whodata_InitializeAcl, pAcl, 1234);
        expect_value(wrap_win_whodata_InitializeAcl, nAclLength, 9);
        expect_value(wrap_win_whodata_InitializeAcl, dwAclRevision, ACL_REVISION);
        will_return(wrap_win_whodata_InitializeAcl, 1);

        will_return(wrap_win_whodata_GetAce, &old_sacl_info);
        will_return(wrap_win_whodata_GetAce, 1);

        expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
        will_return(wrap_win_whodata_AddAce, 1);

        expect_value(wrap_win_whodata_win_alloc, size, 9);
        will_return(wrap_win_whodata_win_alloc, &ace);

        will_return(wrap_win_whodata_CopySid, 1);

        expect_value(wrap_win_whodata_AddAce, pAcl, 1234);
        will_return(wrap_win_whodata_AddAce, 1);

        expect_string(wrap_win_whodata_SetNamedSecurityInfo, pObjectName, "C:\\a\\path");
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, ObjectType, SE_FILE_OBJECT);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, SecurityInfo, SACL_SECURITY_INFORMATION);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidOwner, NULL);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, psidGroup, NULL);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, pDacl, NULL);
        expect_value(wrap_win_whodata_SetNamedSecurityInfo, pSacl, 1234);
        will_return(wrap_win_whodata_SetNamedSecurityInfo, ERROR_SUCCESS);

        // Inside set_privilege
        {
            expect_string(wrap_win_whodata_LookupPrivilegeValue, lpName, "SeSecurityPrivilege");
            will_return(wrap_win_whodata_LookupPrivilegeValue, 234567);
            will_return(wrap_win_whodata_LookupPrivilegeValue, 1);

            expect_value(wrap_win_whodata_AdjustTokenPrivileges, TokenHandle, (HANDLE)123456);
            expect_value(wrap_win_whodata_AdjustTokenPrivileges, DisableAllPrivileges, 0);
            will_return(wrap_win_whodata_AdjustTokenPrivileges, 1);

            expect_string(__wrap__mdebug2, formatted_msg, "(6269): The 'SeSecurityPrivilege' privilege has been removed.");
        }

        will_return(wrap_win_whodata_CloseHandle, 0);
    }

    will_return(wrap_win_whodata_GetSystemTime, &st);

    ret = state_checker(input);

    assert_int_equal(ret, 0);
    assert_memory_equal(&syscheck.wdata.dirs_status[0].last_check, &st, sizeof(SYSTEMTIME));
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_FILE_TYPE);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
    assert_non_null(syscheck.opts[0] & WHODATA_ACTIVE);
}

void test_whodata_audit_start_fail_to_create_directories_hash_table(void **state) {
    int ret;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    ret = whodata_audit_start();

    assert_int_equal(ret, 1);
    assert_null(syscheck.wdata.directories);
}

void test_whodata_audit_start_fail_to_create_fd_hash_table(void **state) {
    int ret;

    expect_function_calls(__wrap_OSHash_Create, 2);
    will_return(__wrap_OSHash_Create, 1234);
    will_return(__wrap_OSHash_Create, NULL);

    ret = whodata_audit_start();

    assert_int_equal(ret, 1);
    assert_ptr_equal(syscheck.wdata.directories, 1234);
    assert_null(syscheck.wdata.fd);
}

void test_whodata_audit_start_success(void **state) {
    wchar_t *str = L"C:";
    wchar_t *volume_name = L"\\\\?\\Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}\\";
    int ret;

    expect_function_calls(__wrap_OSHash_Create, 2);
    will_return(__wrap_OSHash_Create, 1234);
    will_return(__wrap_OSHash_Create, 2345);

    expect_function_call(__wrap_OSHash_SetFreeDataPointer);
    will_return(__wrap_OSHash_SetFreeDataPointer, 0);

    // Inside whodata_list_set_values
    {
        expect_string(__wrap__mdebug1, formatted_msg,
            "(6237): Whodata event queue values for Windows -> max_size:'1024' | max_remove:'102' | alert_threshold:'819'");
    }

    expect_string(__wrap__minfo, formatted_msg, FIM_WHODATA_VOLUMES);

    // Inside get_volume_names
    {
        will_return(wrap_win_whodata_FindFirstVolumeW, volume_name);
        will_return(wrap_win_whodata_FindFirstVolumeW, (HANDLE)123456);

        expect_string(wrap_win_whodata_QueryDosDeviceW, lpDeviceName, L"Volume{6B29FC40-CA47-1067-B31D-00DD010662DA}");
        will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));
        will_return(wrap_win_whodata_QueryDosDeviceW, str);
        will_return(wrap_win_whodata_QueryDosDeviceW, wcslen(str));

        // Inside get_drive_names
        {
            wchar_t *volume_paths = L"A\0C\0\\Some\\path\0";

            expect_memory(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, lpszVolumeName, volume_name, wcslen(volume_name));

            will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 16);
            will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, volume_paths);
            will_return(wrap_win_whodata_GetVolumePathNamesForVolumeNameW, 1);

            expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'A'");
            expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point 'C'");
            expect_string(__wrap__mdebug1, formatted_msg, "(6303): Device 'C' associated with the mounting point '\\Some\\path'");
        }

        expect_value(wrap_win_whodata_FindNextVolumeW, hFindVolume, (HANDLE)123456);
        will_return(wrap_win_whodata_FindNextVolumeW, L"");
        will_return(wrap_win_whodata_FindNextVolumeW, 0);

        will_return(wrap_win_whodata_GetLastError, ERROR_NO_MORE_FILES);

        expect_value(wrap_win_whodata_FindVolumeClose, hFindVolume, (HANDLE)123456);
        will_return(wrap_win_whodata_FindVolumeClose, 1);
    }

    ret = whodata_audit_start();

    assert_int_equal(ret, 0);
    assert_ptr_equal(syscheck.wdata.directories, 1234);
    assert_ptr_equal(syscheck.wdata.fd, 2345);

    // Values modified by whodata_list_set_values
    assert_int_equal(syscheck.w_clist.max_size, 1024);
    assert_int_equal(syscheck.w_clist.max_remove, 102);
    assert_int_equal(syscheck.w_clist.alert_threshold, 819);
}

/**************************************************************************/
int main(void) {
    const struct CMUnitTest tests[] = {
        /* set_winsacl */
        cmocka_unit_test(test_set_winsacl_failed_opening),
        cmocka_unit_test(test_set_winsacl_failed_privileges),
        cmocka_unit_test(test_set_winsacl_failed_security_descriptor),
        cmocka_unit_test(test_set_winsacl_no_need_to_configure_acl),
        cmocka_unit_test(test_set_winsacl_unable_to_get_acl_info),
        cmocka_unit_test(test_set_winsacl_fail_to_alloc_new_sacl),
        cmocka_unit_test(test_set_winsacl_fail_to_initialize_new_sacl),
        cmocka_unit_test(test_set_winsacl_fail_getting_ace_from_old_sacl),
        cmocka_unit_test(test_set_winsacl_fail_adding_old_ace_into_new_sacl),
        cmocka_unit_test(test_set_winsacl_fail_to_alloc_new_ace),
        cmocka_unit_test(test_set_winsacl_fail_to_copy_sid),
        cmocka_unit_test(test_set_winsacl_fail_to_add_ace),
        cmocka_unit_test(test_set_winsacl_fail_to_set_security_info),
        cmocka_unit_test(test_set_winsacl_success),
        /* set_privilege */
        cmocka_unit_test(test_set_privilege_lookup_error),
        cmocka_unit_test(test_set_privilege_adjust_token_error),
        cmocka_unit_test(test_set_privilege_elevate_privilege),
        cmocka_unit_test(test_set_privilege_reduce_privilege),
        /* w_update_sacl */
        cmocka_unit_test(test_w_update_sacl_AllocateAndInitializeSid_error),
        cmocka_unit_test(test_w_update_sacl_OpenProcessToken_error),
        cmocka_unit_test(test_w_update_sacl_add_privilege_error),
        cmocka_unit_test(test_w_update_sacl_GetNamedSecurityInfo_error),
        cmocka_unit_test(test_w_update_sacl_GetAclInformation_error),
        cmocka_unit_test(test_w_update_sacl_alloc_new_sacl_error),
        cmocka_unit_test(test_w_update_sacl_InitializeAcl_error),
        cmocka_unit_test(test_w_update_sacl_alloc_ace_error),
        cmocka_unit_test(test_w_update_sacl_CopySid_error),
        cmocka_unit_test(test_w_update_sacl_old_sacl_GetAce_error),
        cmocka_unit_test(test_w_update_sacl_old_sacl_AddAce_error),
        cmocka_unit_test(test_w_update_sacl_new_sacl_AddAce_error),
        cmocka_unit_test(test_w_update_sacl_SetNamedSecurityInfo_error),
        cmocka_unit_test(test_w_update_sacl_remove_privilege_error),
        cmocka_unit_test(test_w_update_sacl_success),
        /* whodata_check_arch */
        cmocka_unit_test(test_whodata_check_arch_open_registry_key_error),
        cmocka_unit_test(test_whodata_check_arch_query_key_value_error),
        cmocka_unit_test(test_whodata_check_arch_not_supported_arch),
        cmocka_unit_test(test_whodata_check_arch_x86),
        cmocka_unit_test(test_whodata_check_arch_amd64),
        cmocka_unit_test(test_whodata_check_arch_ia64),
        cmocka_unit_test(test_whodata_check_arch_arm64),
        /* whodata_adapt_path */
        cmocka_unit_test(test_whodata_adapt_path_no_changes),
        cmocka_unit_test(test_whodata_adapt_path_convert_system32),
        cmocka_unit_test(test_whodata_adapt_path_convert_syswow64),
        /* whodata_path_filter */
        cmocka_unit_test(test_whodata_path_filter_file_discarded),
        cmocka_unit_test(test_whodata_path_filter_64_bit_system),
        cmocka_unit_test(test_whodata_path_filter_32_bit_system),
        /* get_whodata_path */
        cmocka_unit_test(test_get_whodata_path_error_determining_buffer_size),
        cmocka_unit_test(test_get_whodata_path_error_copying_buffer),
        cmocka_unit_test_teardown(test_get_whodata_path_success, teardown_string),
        /* is_valid_sacl */
        cmocka_unit_test(test_is_valid_sacl_sid_error),
        cmocka_unit_test(test_is_valid_sacl_sacl_not_found),
        cmocka_unit_test(test_is_valid_sacl_ace_not_found),
        cmocka_unit_test(test_is_valid_sacl_not_valid),
        cmocka_unit_test(test_is_valid_sacl_valid),
        /* replace_device_path */
        cmocka_unit_test_setup_teardown(test_replace_device_path_invalid_path, setup_replace_device_path, teardown_replace_device_path),
        cmocka_unit_test_setup_teardown(test_replace_device_path_empty_wdata_device, setup_replace_device_path, teardown_replace_device_path),
        cmocka_unit_test_setup_teardown(test_replace_device_path_device_not_found, setup_replace_device_path, teardown_replace_device_path),
        cmocka_unit_test_setup_teardown(test_replace_device_path_device_found, setup_replace_device_path, teardown_replace_device_path),
        /* get_drive_names */
        cmocka_unit_test(test_get_drive_names_access_denied_error),
        cmocka_unit_test(test_get_drive_names_more_data_error),
        cmocka_unit_test_teardown(test_get_drive_names_success, teardown_wdata_device),
        /* get_volume_names */
        cmocka_unit_test(test_get_volume_names_unable_to_find_first_volume),
        cmocka_unit_test(test_get_volume_names_bad_path),
        cmocka_unit_test(test_get_volume_names_no_dos_device),
        cmocka_unit_test(test_get_volume_names_error_on_next_volume),
        cmocka_unit_test(test_get_volume_names_no_more_files),
        /* notify_SACL_change */
        cmocka_unit_test(test_notify_SACL_change),
        /* whodata_hash_add */
        // TODO: Should we add tests for NULL input parameter?
        cmocka_unit_test(test_whodata_hash_add_unable_to_add),
        cmocka_unit_test(test_whodata_hash_add_duplicate_entry),
        cmocka_unit_test(test_whodata_hash_add_success),
        /* restore_sacls */
        cmocka_unit_test(test_restore_sacls_openprocesstoken_failed),
        cmocka_unit_test(test_restore_sacls_set_privilege_failed),
        cmocka_unit_test_setup_teardown(test_restore_sacls_securityNameInfo_failed, setup_restore_sacls, teardown_restore_sacls),
        cmocka_unit_test_setup_teardown(test_restore_sacls_deleteAce_failed, setup_restore_sacls, teardown_restore_sacls),
        cmocka_unit_test_setup_teardown(test_restore_sacls_SetNamedSecurityInfo_failed, setup_restore_sacls, teardown_restore_sacls),
        cmocka_unit_test_setup_teardown(test_restore_sacls_success, setup_restore_sacls, teardown_restore_sacls),
        /* restore_audit_policies */
        cmocka_unit_test(test_restore_audit_policies_backup_not_found),
        cmocka_unit_test(test_restore_audit_policies_command_failed),
        cmocka_unit_test(test_restore_audit_policies_command2_failed),
        cmocka_unit_test(test_restore_audit_policies_command3_failed),
        cmocka_unit_test(test_restore_audit_policies_success),
        /* audit_restore */
        cmocka_unit_test_setup_teardown(test_audit_restore, setup_restore_sacls, teardown_restore_sacls),
        /* whodata_callback */
        cmocka_unit_test(test_whodata_callback_EvtRenderFailed),
        cmocka_unit_test(test_whodata_callback_invalid_rendered_params),
        cmocka_unit_test(test_whodata_callback_invalid_parameter_event_id),
        cmocka_unit_test(test_whodata_callback_invalid_parameter_path),
        cmocka_unit_test(test_whodata_callback_get_whodata_path_error),
        cmocka_unit_test(test_whodata_callback_whodata_path_filter_error),
        cmocka_unit_test(test_whodata_callback_invalid_parameter_mask),
        cmocka_unit_test(test_whodata_callback_invalid_user_id),
        cmocka_unit_test(test_whodata_callback_unknown_user_id),
        cmocka_unit_test(test_whodata_callback_path),
        cmocka_unit_test(test_whodata_callback_event_wrong_id),
        cmocka_unit_test(test_whodata_callback_event_4656_not_active),
        cmocka_unit_test(test_whodata_callback_event_4656_canceled),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4656_handler_not_removed, setup_whodata_callback, teardown_whodata_callback),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4656_directory, setup_whodata_callback, teardown_whodata_callback),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4656_directory_failed, setup_whodata_callback, teardown_whodata_callback),
        cmocka_unit_test(test_whodata_callback_event_4660_deleted_file),
        cmocka_unit_test(test_whodata_callback_event_4660_not_deleted),
        cmocka_unit_test(test_whodata_callback_event_4658_no_event_to_delete),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_file_deleted, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_file_moved_or_renamed, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_file_not_modified, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_trigger_directory_scan, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_rename_dir, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_new_file_added, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_no_new_files, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4658_scan_aborted, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_no_dir, setup_event_4663_dir, teardown_event_4663_dir),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_invalid_param, setup_event_4663_dir, teardown_event_4663_dir),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_wrong_event_time_param, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_file_time_error, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_timestamp_ok, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_no_event, setup_win_whodata_evt, teardown_win_whodata_evt),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_dir, setup_event_4663_dir, teardown_event_4663_dir),
        cmocka_unit_test_setup_teardown(test_whodata_callback_event_4663_dir_removed, setup_win_whodata_evt, teardown_win_whodata_evt),
        /* check_object_sacl */
        cmocka_unit_test(test_check_object_sacl_open_process_error),
        cmocka_unit_test(test_check_object_sacl_unable_to_set_privilege),
        cmocka_unit_test(test_check_object_sacl_unable_to_retrieve_security_info),
        cmocka_unit_test(test_check_object_sacl_invalid_sacl),
        cmocka_unit_test(test_check_object_sacl_valid_sacl),
        /* whodata_clist_remove */
        cmocka_unit_test_setup_teardown(test_whodata_clist_remove_single_node, setup_w_clist_single_node, teardown_w_clist_single_node),
        cmocka_unit_test_setup_teardown(test_whodata_clist_remove_first_node, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_clist_remove_last_node, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_clist_remove_center_node, setup_w_clist, teardown_w_clist),
        /* free_win_whodata_evt */
        cmocka_unit_test_setup_teardown(test_free_win_whodata_evt, setup_w_clist, teardown_w_clist),
        cmocka_unit_test(test_free_win_whodata_evt_null_event),
        /* compare_timestamp */
        // TODO: Should we add tests for NULL input parameters?
        cmocka_unit_test(test_compare_timestamp_t1_year_bigger),
        cmocka_unit_test(test_compare_timestamp_t2_year_bigger),
        cmocka_unit_test(test_compare_timestamp_t1_month_bigger),
        cmocka_unit_test(test_compare_timestamp_t2_month_bigger),
        cmocka_unit_test(test_compare_timestamp_t1_day_bigger),
        cmocka_unit_test(test_compare_timestamp_t2_day_bigger),
        cmocka_unit_test(test_compare_timestamp_t1_hour_bigger),
        cmocka_unit_test(test_compare_timestamp_t2_hour_bigger),
        cmocka_unit_test(test_compare_timestamp_t1_minute_bigger),
        cmocka_unit_test(test_compare_timestamp_t2_minute_bigger),
        cmocka_unit_test(test_compare_timestamp_t1_seconds_bigger),
        cmocka_unit_test(test_compare_timestamp_t2_seconds_bigger),
        cmocka_unit_test(test_compare_timestamp_equal_dates),
        /* run_whodata_scan */
        cmocka_unit_test(test_run_whodata_scan_invalid_arch),
        cmocka_unit_test(test_run_whodata_scan_no_audit_policies),
        cmocka_unit_test(test_run_whodata_scan_no_auto_audit_policies),
        cmocka_unit_test(test_run_whodata_scan_error_event_channel),
        cmocka_unit_test(test_run_whodata_scan_success),
        /* get_file_time */
        // TODO: Should we add tests for NULL input parameters?
        cmocka_unit_test(test_get_file_time_error),
        cmocka_unit_test(test_get_file_time_success),
        /* set_subscription_query */
        cmocka_unit_test(test_set_subscription_query),
        /* set_policies */
        cmocka_unit_test_teardown(test_set_policies_unable_to_remove_backup_file, teardown_reset_errno),
        cmocka_unit_test(test_set_policies_fail_getting_policies),
        cmocka_unit_test_teardown(test_set_policies_unable_to_open_backup_file, teardown_reset_errno),
        cmocka_unit_test_teardown(test_set_policies_unable_to_open_new_file, teardown_reset_errno),
        cmocka_unit_test(test_set_policies_unable_to_restore_policies),
        cmocka_unit_test(test_set_policies_success),
        /* whodata_list_set_values */
        cmocka_unit_test(test_whodata_list_set_values),
        /* whodata_list_remove_multiple */
        cmocka_unit_test_setup_teardown(test_whodata_list_remove_multiple_remove_none, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_list_remove_multiple_remove_one, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_list_remove_multiple_remove_two, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_list_remove_multiple_remove_more_than_available, setup_w_clist, teardown_w_clist),
        /* whodata_list_add */
        cmocka_unit_test_teardown(test_whodata_list_add_on_empty_list, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_list_add_on_regular_list, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_list_add_trigger_alert, setup_w_clist, teardown_w_clist),
        cmocka_unit_test_setup_teardown(test_whodata_list_add_on_full_list, setup_w_clist, teardown_w_clist),
        /* state_checker */
        cmocka_unit_test_setup_teardown(test_state_checker_no_files_to_check, setup_state_checker, teardown_state_checker),
        cmocka_unit_test_setup_teardown(test_state_checker_file_not_whodata, setup_state_checker, teardown_state_checker),
        cmocka_unit_test_setup_teardown(test_state_checker_file_does_not_exist, setup_state_checker, teardown_state_checker),
        cmocka_unit_test_setup_teardown(test_state_checker_file_with_invalid_sacl, setup_state_checker, teardown_state_checker),
        cmocka_unit_test_setup_teardown(test_state_checker_file_with_valid_sacl, setup_state_checker, teardown_state_checker),
        cmocka_unit_test_setup_teardown(test_state_checker_dir_readded_error, setup_state_checker, teardown_state_checker),
        cmocka_unit_test_setup_teardown(test_state_checker_dir_readded_succesful, setup_state_checker, teardown_state_checker),
        /* whodata_audit_start */
        cmocka_unit_test_teardown(test_whodata_audit_start_fail_to_create_directories_hash_table, teardown_whodata_audit_start),
        cmocka_unit_test_teardown(test_whodata_audit_start_fail_to_create_fd_hash_table, teardown_whodata_audit_start),
        cmocka_unit_test_teardown(test_whodata_audit_start_success, teardown_whodata_audit_start),
    };

    return cmocka_run_group_tests(tests, test_group_setup, test_group_teardown);
}
