/*
 * Wazuh Module for System inventory for Linux
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Sep, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "syscollector.h"

#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <sys/types.h>
#include <sys/vmmeter.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>


#ifdef __MACH__

#include <ctype.h>
#include <libproc.h>
#include <pwd.h>
#include <grp.h>
#include <sys/resource.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <netdb.h>

#if !HAVE_SOCKADDR_SA_LEN
#define SA_LEN(sa)      af_to_len(sa->sa_family)
#if HAVE_SIOCGLIFNUM
#define SS_LEN(sa)      af_to_len(sa->ss_family)
#else
#define SS_LEN(sa)      SA_LEN(sa)
#endif
#else
#define SA_LEN(sa)      sa->sa_len
#endif /* !HAVE_SOCKADDR_SA_LEN */
#endif /* MACH */

void get_system_bsd(hw_entry * info);    // Get system information


#if defined(__MACH__)
OSHash *gateways;

char* sys_parse_pkg(const char * app_folder, const char * timestamp);

// Get installed programs inventory

void sys_packages_bsd(int queue_fd, const char* LOCATION){

    char *format = "pkg";
    char *timestamp = w_get_timestamp(time(NULL));
    struct dirent *de;
    DIR *dr;
    char path[PATH_LENGTH];

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    mtdebug1(WM_SYS_LOGTAG, "Starting installed packages inventory.");

    /* Set positive random ID for each event */

    dr = opendir(MAC_APPS);

    if (dr == NULL) {
        mterror("Unable to open '%s' directory.", MAC_APPS);
    } else {

        while ((de = readdir(dr)) != NULL) {

            // Skip not intereset files
            if (!strncmp(de->d_name, ".", 1)) {
                continue;
            } else if (strstr(de->d_name, ".app")) {
                snprintf(path, PATH_LENGTH - 1, "%s/%s", MAC_APPS, de->d_name);
                char * string = NULL;
                if (string = sys_parse_pkg(path, timestamp), string) {
                    mtdebug2(WM_SYS_LOGTAG, "Sending '%s'", string);
                    wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                    free(string);
                } else
                    mterror(WM_SYS_LOGTAG, "Unable to get package information for '%s'", de->d_name);
            }
        }
        closedir(dr);
    }

    dr = opendir(UTILITIES);

    if (dr == NULL) {
        mterror("Unable to open '%s' directory.", UTILITIES);
    } else {

        while ((de = readdir(dr)) != NULL) {

            // Skip not intereset files
            if (!strncmp(de->d_name, ".", 1)) {
                continue;
            } else if (strstr(de->d_name, ".app")) {
                snprintf(path, PATH_LENGTH - 1, "%s/%s", UTILITIES, de->d_name);
                char * string = NULL;
                if (string = sys_parse_pkg(path, timestamp), string) {
                    mtdebug2(WM_SYS_LOGTAG, "sys_packages_bsd() sending '%s'", string);
                    wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                    free(string);
                } else
                    mterror(WM_SYS_LOGTAG, "Unable to get package information for '%s'", de->d_name);
            }
        }
        closedir(dr);
    }

    /* Get Homebrew applications */

    dr = opendir(HOMEBREW_APPS);

    if (dr == NULL) {
        mtdebug1("No homebrew applications found in '%s'", HOMEBREW_APPS);
    } else {

        DIR *dir;
        struct dirent *version = NULL;

        while ((de = readdir(dr)) != NULL) {

            if (strncmp(de->d_name, ".", 1) == 0) {
                continue;
            }

            program_entry_data * entry_data = NULL;

            entry_data = init_program_data_entry();

            os_strdup(format, entry_data->format);
            os_strdup(de->d_name, entry_data->name);

            snprintf(path, PATH_LENGTH - 1, "%s/%s", HOMEBREW_APPS, de->d_name);
            os_strdup(path, entry_data->location);
            os_strdup("homebrew", entry_data->source);

            dir = opendir(path);
            if (dir != NULL) {
                while ((version = readdir(dir)) != NULL) {
                    if (strncmp(version->d_name, ".", 1) == 0 || strncmp(version->d_name, "..", 2) == 0) {
                        continue;
                    }

                    os_strdup(version->d_name, entry_data->version);
                    snprintf(path, PATH_LENGTH - 1, "%s/%s/%s/.brew/%s.rb", HOMEBREW_APPS, de->d_name, version->d_name, de->d_name);

                    char read_buff[OS_MAXSTR];
                    FILE *fp;

                    if ((fp = fopen(path, "r"))) {
                        int found = 0;
                        while(fgets(read_buff, OS_MAXSTR - 1, fp) != NULL && !found){
                            if (strstr(read_buff, "desc \"") != NULL) {
                                found = 1;
                                char ** parts = OS_StrBreak('"', read_buff, 3);
                                os_strdup(parts[1], entry_data->description);
                                int i;
                                for (i = 0; parts[i]; ++i) {
                                    free(parts[i]);
                                }
                                free(parts);
                            }
                        }
                        fclose(fp);
                    }
                }
                closedir(dir);
            }

            // Check if it is necessary to create a program event
            char * string = NULL;
            if (string = analyze_program(entry_data, timestamp), string) {
                mtdebug2(WM_SYS_LOGTAG, "sys_packages_bsd() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                free(string);
            }
        }
        closedir(dr);
    }

    free(timestamp);

    // Checking for uninstalled programs
    check_uninstalled_programs();
}

char* sys_parse_pkg(const char * app_folder, const char * timestamp) {

    char *format = "pkg";
    char read_buff[OS_MAXSTR];
    char filepath[PATH_LENGTH];
    FILE *fp;
    int i = 0;
    int invalid = 0;

    program_entry_data * entry_data = NULL;

    snprintf(filepath, PATH_LENGTH - 1, "%s/%s", app_folder, INFO_FILE);
    memset(read_buff, 0, OS_MAXSTR);

    if ((fp = fopen(filepath, "r"))) {

        entry_data = init_program_data_entry();

        os_strdup(format, entry_data->format);

        // Check if valid Info.plist file (not an Apple binary property list)
        if (fgets(read_buff, OS_MAXSTR - 1, fp) != NULL) {
            if (strncmp(read_buff, "<?xml", 5)) {   // Invalid file
                mtdebug1(WM_SYS_LOGTAG, "Unable to read package information from '%s' (invalid format)", filepath);
                invalid = 1;
            } else {
                // Valid Info.plist file
                while(fgets(read_buff, OS_MAXSTR - 1, fp) != NULL) {

                    if (strstr(read_buff, "CFBundleName")) {

                        if (strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 4);
                            char ** _parts = OS_StrBreak('<', parts[3], 2);

                            os_strdup(_parts[0], entry_data->name);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                        else if((fgets(read_buff, OS_MAXSTR - 1, fp) != NULL) && strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 2);
                            char ** _parts = OS_StrBreak('<', parts[1], 2);

                            os_strdup(_parts[0], entry_data->name);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }

                    } else if (strstr(read_buff, "CFBundleShortVersionString")){
                        if (strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 4);
                            char ** _parts = OS_StrBreak('<', parts[3], 2);

                            os_strdup(_parts[0], entry_data->version);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                        else if ((fgets(read_buff, OS_MAXSTR - 1, fp) != NULL) && strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 2);
                            char ** _parts = OS_StrBreak('<', parts[1], 2);

                            os_strdup(_parts[0], entry_data->version);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                    } else if (strstr(read_buff, "LSApplicationCategoryType")){
                        if (strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 4);
                            char ** _parts = OS_StrBreak('<', parts[3], 2);

                            os_strdup(_parts[0], entry_data->group);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                        else if((fgets(read_buff, OS_MAXSTR - 1, fp) != NULL) && strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 2);
                            char ** _parts = OS_StrBreak('<', parts[1], 2);

                            os_strdup(_parts[0], entry_data->group);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                    } else if (strstr(read_buff, "CFBundleIdentifier")){
                        if (strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 4);
                            char ** _parts = OS_StrBreak('<', parts[3], 2);

                            os_strdup(_parts[0], entry_data->description);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                        else if((fgets(read_buff, OS_MAXSTR - 1, fp) != NULL) && strstr(read_buff, "<string>")){
                            char ** parts = OS_StrBreak('>', read_buff, 2);
                            char ** _parts = OS_StrBreak('<', parts[1], 2);

                            os_strdup(_parts[0], entry_data->description);

                            for (i = 0; _parts[i]; i++) {
                                os_free(_parts[i]);
                            }
                            os_free(_parts);

                            for (i = 0; parts[i]; i++) {
                                os_free(parts[i]);
                            }
                            os_free(parts);
                        }
                    }
                }
            }
        } else {
            mtwarn(WM_SYS_LOGTAG, "Unable to read file '%s'", filepath);
        }

        if (strstr(app_folder, "/Utilities") != NULL) {
            os_strdup("utilities", entry_data->source);
        } else {
            os_strdup("applications", entry_data->source);
        }
        os_strdup(app_folder, entry_data->location);

        if (invalid) {
            char * program_name;
            char * end;

            // Extract program name from the path
            program_name = strrchr(app_folder, '/');
            program_name++;
            end = strchr(program_name, '.');
            *end = '\0';

            os_strdup(program_name, entry_data->name);
        }

        // Check if it is necessary to create a program event
        char * string = NULL;
        string = analyze_program(entry_data, timestamp);

        fclose(fp);
        return string;
    }

    return NULL;
}

#elif defined(__FreeBSD__)

// Get installed programs inventory

void sys_packages_bsd(int queue_fd, const char* LOCATION){

    char *format = "pkg";
    char read_buff[OS_MAXSTR];
    char *command;
    FILE *output;
    int i;
    char *timestamp = w_get_timestamp(time(NULL));
    int status;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    mtdebug1(WM_SYS_LOGTAG, "Starting installed packages inventory.");

    /* Set positive random ID for each event */

    os_calloc(COMMAND_LENGTH, sizeof(char), command);
    snprintf(command, COMMAND_LENGTH - 1, "%s", "pkg query -a '\%n|%m|%v|%q|\%c'");

    memset(read_buff, 0, OS_MAXSTR);

    if ((output = popen(command, "r"))){

        while(fgets(read_buff, OS_MAXSTR, output)){

            program_entry_data * entry_data = NULL;

            char ** parts = NULL;
            char ** description = NULL;

            entry_data = init_program_data_entry();

            os_strdup(format, entry_data->format);

            parts = OS_StrBreak('|', read_buff, 5);
            os_strdup(parts[0], entry_data->name);
            os_strdup(parts[1], entry_data->vendor);
            os_strdup(parts[2], entry_data->version);
            os_strdup(parts[3], entry_data->architecture);

            description = OS_StrBreak('\n', parts[4], 2);
            os_strdup(description[0], entry_data->description);
            for (i=0; description[i]; i++){
                free(description[i]);
            }
            for (i=0; parts[i]; i++){
                free(parts[i]);
            }
            free(description);
            free(parts);

            // Check if it is necessary to create a program event
            char * string = NULL;
            if (string = analyze_program(entry_data, timestamp), string) {
                mtdebug2(WM_SYS_LOGTAG, "sys_packages_bsd() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                free(string);
            }
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'pkg' returned %d getting software inventory.", status);
        }
    }else{
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s' to get software inventory.", command);
    }
    free(command);
    free(timestamp);

    // Checking for uninstalled programs
    check_uninstalled_programs();
}

#endif

// Get hardware inventory

void sys_hw_bsd(int queue_fd, const char* LOCATION){

    char *timestamp = w_get_timestamp(time(NULL));

    hw_entry * hw_data = NULL;

    mtdebug1(WM_SYS_LOGTAG, "Starting Hardware inventory.");

    hw_data = init_hw_data();

    /* Motherboard serial-number */
#if defined(__OpenBSD__)

    char serial[SERIAL_LENGTH];
    int mib[2];
    size_t len;
    mib[0] = CTL_HW;
    mib[1] = HW_SERIALNO;
    len = sizeof(serial);
    if (!sysctl(mib, 2, &serial, &len, NULL, 0)){
        os_strdup(serial, hw_data->board_serial);
    }else{
        mtdebug1(WM_SYS_LOGTAG, "Fail getting serial number due to (%s)", strerror(errno));
    }

#elif defined(__MACH__)

    char *serial = NULL;
    char *command;
    FILE *output;
    char read_buff[SERIAL_LENGTH];
    int status;

    memset(read_buff, 0, SERIAL_LENGTH);
    command = "system_profiler SPHardwareDataType | grep Serial";
    if (output = popen(command, "r"), output) {
        if(!fgets(read_buff, SERIAL_LENGTH, output)){
            mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'", command);
        } else {
            char ** parts = NULL;
            parts = OS_StrBreak('\n', read_buff, 2);
            if (parts[0]) {
                char *serial_ref = strchr(parts[0], ':');
                if (serial_ref){
                    serial = strdup(serial_ref + 2);
                }
            }

            int i;
            for (i=0; parts[i]; i++){
                free(parts[i]);
            }

            free(parts);
        }

        if (status = pclose(output), status) {
            mtinfo(WM_SYS_LOGTAG, "Command 'system_profiler' returned %d getting board serial.", status);
        }
    } else {
        mtwarn(WM_SYS_LOGTAG, "Couldn't get board serial for hardware inventory.");
    }

    if (!serial) {
        serial = strdup("unknown");
    }

    os_strdup(serial, hw_data->board_serial);
    os_free(serial);
#else
    os_strdup("unknown", hw_data->board_serial);
#endif

    /* Get CPU and memory information */
    get_system_bsd(hw_data);

    // Check if it is necessary to create a hardware event
    char * string = NULL;
    if (string = analyze_hw(hw_data, timestamp), string) {
        mtdebug2(WM_SYS_LOGTAG, "Sending '%s'", string);
        SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
        free(string);
    }

    free(timestamp);
}

void get_system_bsd(hw_entry * info) {

    int mib[2];
    size_t len;

    /* CPU Name */
    char cpu_name[1024];
    mib[0] = CTL_HW;
    mib[1] = HW_MODEL;
    len = sizeof(cpu_name);
    if (!sysctl(mib, 2, &cpu_name, &len, NULL, 0)){
        info->cpu_name = strdup(cpu_name);
    }else{
        info->cpu_name = strdup("unknown");
        mtdebug1(WM_SYS_LOGTAG, "Fail getting CPU name due to (%s)", strerror(errno));
    }

    /* Number of cores */
    info->cpu_cores = get_nproc();

    /* CPU clockrate (MHz) */
#if defined(__OpenBSD__)

    unsigned long cpu_MHz;
    mib[0] = CTL_HW;
    mib[1] = HW_CPUSPEED;
    len = sizeof(cpu_MHz);
    if (!sysctl(mib, 2, &cpu_MHz, &len, NULL, 0)){
        info->cpu_MHz = (double)cpu_MHz/1000000.0;
    }else{
        mtdebug1(WM_SYS_LOGTAG, "Failed getting CPU clockrate due to (%s)", strerror(errno));
    }

#elif defined(__FreeBSD__) || defined(__MACH__)

    char *clockrate;
    clockrate = calloc(CLOCK_LENGTH, sizeof(char));

#if defined(__FreeBSD__)
    snprintf(clockrate, CLOCK_LENGTH-1, "%s", "hw.clockrate");
#elif defined(__MACH__)
    snprintf(clockrate, CLOCK_LENGTH-1, "%s", "hw.cpufrequency");
#endif

    unsigned long cpu_MHz;
    len = sizeof(cpu_MHz);
    if (!sysctlbyname(clockrate, &cpu_MHz, &len, NULL, 0)){
        info->cpu_MHz = (double)cpu_MHz/1000000.0;
    }else{
        mtdebug1(WM_SYS_LOGTAG, "Fail getting CPU clockrate due to (%s)", strerror(errno));
    }

    free(clockrate);

#endif

    /* Total memory RAM */
    uint64_t cpu_ram;
    mib[0] = CTL_HW;

#if defined(__MACH__)
    mib[1] = HW_MEMSIZE;
#else
    mib[1] = HW_PHYSMEM;
#endif

    len = sizeof(cpu_ram);
    if (!sysctl(mib, 2, &cpu_ram, &len, NULL, 0)){
        uint64_t cpu_ram_kb = cpu_ram / 1024;
        info->ram_total = cpu_ram_kb;
    }else{
        mtdebug1(WM_SYS_LOGTAG, "Fail getting total RAM due to (%s)", strerror(errno));
    }

    /* Free memory RAM and usage */
#if defined(__FreeBSD__)

    u_int page_size;
    struct vmtotal vmt;

    len = sizeof(vmt);

    if (!sysctlbyname("vm.vmtotal", &vmt, &len, NULL, 0)) {

        len = sizeof(page_size);
        if (!sysctlbyname("vm.stats.vm.v_page_size", &page_size, &len, NULL, 0)){
            uint64_t cpu_free_kb = (vmt.t_free * (uint64_t)page_size) / 1024;
            info->ram_free = cpu_free_kb;

            if (info->ram_total > 0) {
                info->ram_usage = 100 - (info->ram_free * 100 / info->ram_total);
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Fail getting pages size due to (%s)", strerror(errno));
        }

    } else {
        mtdebug1(WM_SYS_LOGTAG, "Fail getting RAM free due to (%s)", strerror(errno));
    }

#elif defined(__MACH__)

    u_int page_size = 0;
    uint64_t free_pages = 0;

    len = sizeof(page_size);

    if (!sysctlbyname("vm.pagesize", &page_size, &len, NULL, 0)) {

        len = sizeof(free_pages);
        if (!sysctlbyname("vm.page_free_count", &free_pages, &len, NULL, 0)) {

            uint64_t cpu_free_kb = (free_pages * (uint64_t)page_size) / 1024;
            info->ram_free = cpu_free_kb;

            if (info->ram_free > info->ram_total) {
                mwarn("Failed reading free memory RAM.");
                info->ram_free = info->ram_total;
            }

            if (info->ram_total > 0) {
                info->ram_usage = 100 - (info->ram_free * 100 / info->ram_total);
            }

        } else {
            mtdebug1(WM_SYS_LOGTAG, "Fail getting free pages due to (%s)", strerror(errno));
        }
    } else {
        mtdebug1(WM_SYS_LOGTAG, "Fail getting pages size due to (%s)", strerror(errno));
    }

#endif

}

// Get network inventory

void sys_network_bsd(int queue_fd, const char* LOCATION){

    char ** ifaces_list;
    int i = 0, size_ifaces = 0;
    struct ifaddrs *ifaddrs_ptr = NULL, *ifa;
    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    mtdebug1(WM_SYS_LOGTAG, "Starting network inventory.");

    if (getifaddrs(&ifaddrs_ptr) == -1){
        mterror(WM_SYS_LOGTAG, "Extracting the interfaces of the system.");
        free(timestamp);
        if (ifaddrs_ptr) {
            freeifaddrs(ifaddrs_ptr);
        }
        return;
    }

    for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next){
        i++;
    }

    if (i == 0) {
        mterror(WM_SYS_LOGTAG, "No interface found. Network inventory suspended.");
        free(timestamp);
        return;
    }

    os_calloc(i, sizeof(char *), ifaces_list);

    /* Create interfaces list */
    size_ifaces = getIfaceslist(ifaces_list, ifaddrs_ptr);

    if(!ifaces_list[size_ifaces-1]){
        mtinfo(WM_SYS_LOGTAG, "Not found any interface. Network inventory suspended.");
        free(timestamp);
        return;
    }

#if defined(__MACH__)
    gateways = OSHash_Create();
    OSHash_SetFreeDataPointer(gateways, (void (*)(void *)) freegate);
    if (getGatewayList(gateways) < 0){
        mtwarn(WM_SYS_LOGTAG, "Unable to obtain the Default Gateway list.");
    }
#endif

    for (i=0; i < size_ifaces; i++){

        interface_entry_data * entry_data = NULL;

        gateway *gate = NULL;
        #if defined(__MACH__)
        gate = (gateway *)OSHash_Get(gateways, ifaces_list[i]);
        #endif

        if (entry_data = getNetworkIface_bsd(ifaces_list[i], ifaddrs_ptr, gate), entry_data) {
            // Check if it is necessary to create an interface event
            char * string = NULL;
            if (string = analyze_interface(entry_data, timestamp), string) {
                mtdebug2(WM_SYS_LOGTAG, "sys_network_bsd() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                free(string);
            }
        } else {
            mdebug2("Couldn't get the data of the interface: '%s'", ifaces_list[i]);
        }
    }

#if defined(__MACH__)
    OSHash_Free(gateways);
#endif
    freeifaddrs(ifaddrs_ptr);
    for (i=0; ifaces_list[i]; i++){
        free(ifaces_list[i]);
    }
    free(ifaces_list);
    free(timestamp);

    // Checking for disabled interfaces
    check_disabled_interfaces();
}

interface_entry_data * getNetworkIface_bsd(char *iface_name, struct ifaddrs *ifaddrs_ptr, __attribute__((unused)) gateway* gate){

    struct ifaddrs *ifa;
    int family = 0;

    interface_entry_data * entry_data = init_interface_data_entry();

    os_strdup(iface_name, entry_data->name);

    entry_data->ipv4 = init_net_addr();
    os_malloc(sizeof(char *), entry_data->ipv4->address);
    os_malloc(sizeof(char *), entry_data->ipv4->netmask);
    os_malloc(sizeof(char *), entry_data->ipv4->broadcast);
    int addr4 = 0, nmask4 = 0, bcast4 = 0;

    entry_data->ipv6 = init_net_addr();
    os_malloc(sizeof(char *), entry_data->ipv6->address);
    os_malloc(sizeof(char *), entry_data->ipv6->netmask);
    os_malloc(sizeof(char *), entry_data->ipv6->broadcast);
    int addr6 = 0, nmask6 = 0, bcast6 = 0;

    for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next){

        if (strcmp(iface_name, ifa->ifa_name)){
            continue;
        }
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET){

            if (ifa->ifa_addr){

                void * addr_ptr;
                /* IPv4 Address */

                addr_ptr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;

                char host[NI_MAXHOST];
                inet_ntop(ifa->ifa_addr->sa_family,
                        addr_ptr,
                        host,
                        sizeof (host));

                os_strdup(host, entry_data->ipv4->address[addr4]);
                os_realloc(entry_data->ipv4->address, (addr4 + 2) * sizeof(char *), entry_data->ipv4->address);
                addr4++;

                /* Netmask Address */
                addr_ptr = &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;

                char netmask[NI_MAXHOST];
                inet_ntop(ifa->ifa_netmask->sa_family,
                        addr_ptr,
                        netmask,
                        sizeof (netmask));

                os_strdup(netmask, entry_data->ipv4->netmask[nmask4]);
                os_realloc(entry_data->ipv4->netmask, (nmask4 + 2) * sizeof(char *), entry_data->ipv4->netmask);
                nmask4++;

                /* Broadcast Address */
                addr_ptr = &((struct sockaddr_in *) ifa->ifa_dstaddr)->sin_addr;

                char broadaddr[NI_MAXHOST];
                inet_ntop(ifa->ifa_dstaddr->sa_family,
                        addr_ptr,
                        broadaddr,
                        sizeof (broadaddr));

                os_strdup(broadaddr, entry_data->ipv4->broadcast[bcast4]);
                os_realloc(entry_data->ipv4->broadcast, (bcast4 + 2) * sizeof(char *), entry_data->ipv4->broadcast);
                bcast4++;
            }

        } else if (family == AF_INET6){

            if (ifa->ifa_addr){

                void * addr_ptr;

                /* IPv6 Address */
                addr_ptr = &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;

                char host[NI_MAXHOST];
                inet_ntop(ifa->ifa_addr->sa_family,
                        addr_ptr,
                        host,
                        sizeof (host));

                os_strdup(host, entry_data->ipv6->address[addr6]);
                os_realloc(entry_data->ipv6->address, (addr6 + 2) * sizeof(char *), entry_data->ipv6->address);
                addr6++;

                /* Netmask address */
                if (ifa->ifa_netmask){
                    addr_ptr = &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;

                    char netmask6[NI_MAXHOST];
                    inet_ntop(ifa->ifa_netmask->sa_family,
                            addr_ptr,
                            netmask6,
                            sizeof (netmask6));

                    os_strdup(netmask6, entry_data->ipv6->netmask[nmask6]);
                    os_realloc(entry_data->ipv6->netmask, (nmask6 + 2) * sizeof(char *), entry_data->ipv6->netmask);
                    nmask6++;
                }

                /* Broadcast address */
                if (ifa->ifa_dstaddr){
                    addr_ptr = &((struct sockaddr_in6 *) ifa->ifa_dstaddr)->sin6_addr;

                    char broadaddr6[NI_MAXHOST];
                    inet_ntop(ifa->ifa_dstaddr->sa_family,
                            addr_ptr,
                            broadaddr6,
                            sizeof (broadaddr6));

                    os_strdup(broadaddr6, entry_data->ipv6->broadcast[bcast6]);
                    os_realloc(entry_data->ipv6->broadcast, (bcast6 + 2) * sizeof(char *), entry_data->ipv6->broadcast);
                    bcast6++;
                }
            }

        } else if (family == AF_LINK && ifa->ifa_data != NULL){

            char * type;
            char * state;

            struct sockaddr_dl * sdl;
            sdl = (struct sockaddr_dl *) ifa->ifa_addr;

            os_calloc(TYPE_LENGTH + 1, sizeof(char), type);
            snprintf(type, TYPE_LENGTH, "%s", "unknown");

            /* IF Type */
            if (sdl->sdl_type == IFT_ETHER){
                snprintf(type, TYPE_LENGTH, "%s", "ethernet");
            }else if (sdl->sdl_type == IFT_ISO88023){
                snprintf(type, TYPE_LENGTH, "%s", "CSMA/CD");
            }else if (sdl->sdl_type == IFT_ISO88024 || sdl->sdl_type == IFT_ISO88025){
                snprintf(type, TYPE_LENGTH, "%s", "token ring");
            }else if (sdl->sdl_type == IFT_FDDI){
                snprintf(type, TYPE_LENGTH, "%s", "FDDI");
            }else if (sdl->sdl_type == IFT_PPP){
                snprintf(type, TYPE_LENGTH, "%s", "point-to-point");
            }else if (sdl->sdl_type == IFT_ATM){
                snprintf(type, TYPE_LENGTH, "%s", "ATM");
            }else{
                snprintf(type, TYPE_LENGTH, "%s", "unknown");
            }

            os_strdup(type, entry_data->type);
            free(type);

            os_calloc(STATE_LENGTH + 1, sizeof(char), state);

            /* Oper status based on flags */
            if (ifa->ifa_flags & IFF_UP){
                snprintf(state, STATE_LENGTH, "%s", "up");
            }else{
                snprintf(state, STATE_LENGTH, "%s", "down");
            }
            os_strdup(state, entry_data->state);
            free(state);

            /* MAC address */
            char MAC[MAC_LENGTH] = "";
            char *mac_addr = &MAC[0];
            int mac_offset;

            for (mac_offset = 0; mac_offset < 6; mac_offset++){
                unsigned char byte;
                byte = (unsigned char)(LLADDR(sdl)[mac_offset]);
                mac_addr += sprintf(mac_addr, "%.2X", byte);
                if (mac_offset != 5){
                    mac_addr += sprintf(mac_addr, "%c", ':');
                }
            }
            os_strdup(MAC, entry_data->mac);

            /* Stats and other information */
            struct if_data *stats = ifa->ifa_data;
            entry_data->tx_packets = stats->ifi_opackets;
            entry_data->rx_packets = stats->ifi_ipackets;
            entry_data->tx_bytes = stats->ifi_obytes;
            entry_data->rx_bytes = stats->ifi_ibytes;
            entry_data->tx_errors = stats->ifi_oerrors;
            entry_data->rx_errors = stats->ifi_ierrors;
            entry_data->rx_dropped = stats->ifi_iqdrops;

            entry_data->mtu = stats->ifi_mtu;
        }
    }

    entry_data->ipv4->address[addr4] = NULL;
    entry_data->ipv4->netmask[nmask4] = NULL;
    entry_data->ipv4->broadcast[bcast4] = NULL;
    entry_data->ipv6->address[addr6] = NULL;
    entry_data->ipv6->netmask[nmask6] = NULL;
    entry_data->ipv6->broadcast[bcast6] = NULL;

    /* Add address information to the structure */

    #if defined(__MACH__)
    if(gate) {
        os_strdup(gate->addr, entry_data->ipv4->gateway);
    }
    #endif

    os_strdup("unknown", entry_data->ipv4->dhcp);
    os_strdup("unknown", entry_data->ipv6->dhcp);

    return entry_data;
}

#if defined(__MACH__)

static int af_to_len(int af){
    switch (af) {
        case AF_INET: return sizeof (struct sockaddr_in);
        #if defined(AF_INET6) && HAVE_SOCKADDR_IN6
        case AF_INET6: return sizeof (struct sockaddr_in6);
        #endif
        #if defined(AF_LINK) && HAVE_SOCKADDR_DL
        case AF_LINK: return sizeof (struct sockaddr_dl);
        #endif
    }
    return sizeof (struct sockaddr);
}

static int string_from_sockaddr (struct sockaddr *addr, char *buffer, size_t buflen) {
    struct sockaddr* bigaddr = 0;
    int failure;
    struct sockaddr* gniaddr;
    socklen_t gnilen;

    if (!addr || addr->sa_family == AF_UNSPEC)
        return -1;

    if (SA_LEN(addr) < af_to_len(addr->sa_family)) {
        gnilen = af_to_len(addr->sa_family);
        bigaddr = calloc(1, gnilen);
        if (!bigaddr)
        return -1;
        memcpy(bigaddr, addr, SA_LEN(addr));
    #if HAVE_SOCKADDR_SA_LEN
        bigaddr->sa_len = gnilen;
    #endif
        gniaddr = bigaddr;
    } else {
        gnilen = SA_LEN(addr);
        gniaddr = addr;
    }

    failure = getnameinfo (gniaddr, gnilen,
                            buffer, buflen,
                            NULL, 0,
                            NI_NUMERICHOST);

    if (bigaddr) {
        free(bigaddr);
        bigaddr = 0;
    }

    if (failure) {
        size_t n, len;
        char *ptr;
        const char *data;

        len = SA_LEN(addr);

    #if HAVE_AF_LINK
        if (addr->sa_family == AF_LINK) {
        struct sockaddr_dl *dladdr = (struct sockaddr_dl *)addr;
        len = dladdr->sdl_alen;
        data = LLADDR(dladdr);
        } else {
    #endif
            /* Unknown sockaddr */
            len -= (sizeof (struct sockaddr) - sizeof (addr->sa_data));
            data = addr->sa_data;
    #if HAVE_AF_LINK
        }
    #endif

        if (buflen < 3 * len)
        return -1;

        ptr = buffer;
        buffer[0] = '\0';

        for (n = 0; n < len; ++n) {
        sprintf (ptr, "%02x:", data[n] & 0xff);
        ptr += 3;
        }
        if (len)
        *--ptr = '\0';
    }

    if (!buffer[0])
        return -1;

    return 0;
}

int getGatewayList(OSHash *gateway_list){
    int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_FLAGS, RTF_UP | RTF_GATEWAY };
    size_t len;
    char *buffer = NULL, *ptr, *end;
    int ret;
    char ifnamebuf[IF_NAMESIZE];
    char *ifname;

    do {
        if (sysctl (mib, 6, 0, &len, 0, 0) < 0) {
        free (buffer);
        return -1;
        }

        ptr = realloc(buffer, len);
        if (!ptr) {
            free (buffer);
            return -1;
        }

        buffer = ptr;

        ret = sysctl (mib, 6, buffer, &len, 0, 0);
    } while (ret != 0);

    if (ret < 0) {
        free (buffer);
        return -1;
    }

    ptr = buffer;
    end = buffer + len;
    while (ptr + sizeof (struct rt_msghdr) <= end) {
        struct rt_msghdr *msg = (struct rt_msghdr *)ptr;
        char *msgend = (char *)msg + msg->rtm_msglen;
        int addrs = msg->rtm_addrs;
        int addr = RTA_DST;

        if (msgend > end)
            break;

        ifname = if_indextoname (msg->rtm_index, ifnamebuf);

        if (!ifname) {
            ptr = msgend;
            continue;
        }

        ptr = (char *)(msg + 1);
        while (ptr + sizeof (struct sockaddr) <= msgend && addrs) {
            struct sockaddr *sa = (struct sockaddr *)ptr;
            int len = SA_LEN(sa);

            if (!len)
                len = 4;
            else
                len = (len + 3) & ~3;

            if (ptr + len > msgend)
                break;

            while (!(addrs & addr))
                addr <<= 1;

            addrs &= ~addr;

            if (addr == RTA_DST) {
                if (sa->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)sa;
                if (sin->sin_addr.s_addr != INADDR_ANY)
                    break;
        #ifdef AF_INET6
                } else if (sa->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
                if (memcmp (&sin6->sin6_addr, &in6addr_any, sizeof (in6addr_any)) != 0)
                    break;
        #endif
                } else {
                    break;
                }
            }

            if (addr == RTA_GATEWAY) {
                struct gateway *gate;
                os_calloc(1, sizeof (struct gateway), gate);
                char strbuf[256];

                if (string_from_sockaddr (sa, strbuf, sizeof(strbuf)) != 0) {
                    os_free(gate);
                    continue;
                }
                os_calloc(256, sizeof (char), gate->addr);
                snprintf(gate->addr, 255, "%s", strbuf);
                #ifdef RTF_IFSCOPE
                gate->isdefault = !(msg->rtm_flags & RTF_IFSCOPE);
                #else
                gate->isdefault = 1;
                #endif
                OSHash_Add(gateway_list, ifname, gate);
                mdebug2("Gateway of interface %s : %s Default: %d", ifname, gate->addr, gate->isdefault);
            }

            /* These are aligned on a 4-byte boundary */
            ptr += len;
        }

        ptr = msgend;
    }

    free (buffer);

    return 0;
}

char *get_port_state(int state) {
    char *port_state;
    os_calloc(STATE_LENGTH, sizeof(char), port_state);

    switch(state){
        case TSI_S_ESTABLISHED:
            snprintf(port_state, STATE_LENGTH, "%s", "established");
            break;
        case TSI_S_SYN_SENT:
            snprintf(port_state, STATE_LENGTH, "%s", "syn_sent");
            break;
        case TSI_S_SYN_RECEIVED:
            snprintf(port_state, STATE_LENGTH, "%s", "syn_recv");
            break;
        case TSI_S_FIN_WAIT_1:
            snprintf(port_state, STATE_LENGTH, "%s", "fin_wait1");
            break;
        case TSI_S_FIN_WAIT_2:
            snprintf(port_state, STATE_LENGTH, "%s", "fin_wait2");
            break;
        case TSI_S_TIME_WAIT:
            snprintf(port_state, STATE_LENGTH, "%s", "time_wait");
            break;
        case TSI_S_CLOSED:
            snprintf(port_state, STATE_LENGTH, "%s", "close");
            break;
        case TSI_S__CLOSE_WAIT:
            snprintf(port_state, STATE_LENGTH, "%s", "close_wait");
            break;
        case TSI_S_LAST_ACK:
            snprintf(port_state, STATE_LENGTH, "%s", "last_ack");
            break;
        case TSI_S_LISTEN:
            snprintf(port_state, STATE_LENGTH, "%s", "listening");
            break;
        case TSI_S_CLOSING:
            snprintf(port_state, STATE_LENGTH, "%s", "closing");
            break;
        default:
            snprintf(port_state, STATE_LENGTH, "%s", "unknown");
            break;
    }
    return port_state;
}

void sys_ports_mac(int queue_fd, const char* WM_SYS_LOCATION, int check_all) {

    time_t now = time(NULL);
    struct tm localtm;
    localtime_r(&now, &localtm);

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    const int usec = 1000000 / wm_max_eps;

    mtdebug1(WM_SYS_LOGTAG, "Starting ports inventory.");

    pid_t * pids = NULL;
    int32_t maxproc;
    size_t len = sizeof(maxproc);
    sysctlbyname("kern.maxproc", &maxproc, &len, NULL, 0);

    os_calloc(maxproc, 1, pids);
    int count = proc_listallpids(pids, maxproc);

    int index;
    for(index = 0; index < count; ++index) {
        pid_t pid = pids[index];
        // Figure out the size of the buffer needed to hold the list of open FDs
        int bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
        if (bufferSize == -1) {
            mterror(WM_SYS_LOGTAG, "Unable to get open file handles for %d", pid);
            continue;
        }

        // Get the list of open FDs
        struct proc_fdinfo *procFDInfo;
        os_malloc(bufferSize, procFDInfo);
        proc_pidinfo(pid, PROC_PIDLISTFDS, 0, procFDInfo, bufferSize);
        int numberOfProcFDs = bufferSize / PROC_PIDLISTFD_SIZE;

        int i;
        for(i = 0; i < numberOfProcFDs; i++) {
            if(procFDInfo[i].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct  proc_bsdinfo pbsd;
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbsd, PROC_PIDTBSDINFO_SIZE);
            struct socket_fdinfo socketInfo;
            int bytesUsed = proc_pidfdinfo(pid, procFDInfo[i].proc_fd, PROC_PIDFDSOCKETINFO, &socketInfo, PROC_PIDFDSOCKETINFO_SIZE);

            if (bytesUsed != PROC_PIDFDSOCKETINFO_SIZE) {
                continue;
            }

            if (socketInfo.psi.soi_kind != SOCKINFO_TCP && socketInfo.psi.soi_kind != SOCKINFO_IN) {
                continue;
            }

            port_entry_data * entry_data = NULL;

            char laddr[NI_MAXHOST];
            char faddr[NI_MAXHOST];

            switch(socketInfo.psi.soi_family) {
                case AF_INET6: {
                    struct sockaddr_in6 lsin6 = {0};
                    lsin6.sin6_family = AF_INET6;
                    lsin6.sin6_addr  = (struct in6_addr)socketInfo.psi.soi_proto.pri_in.insi_laddr.ina_6;
                    getnameinfo((struct sockaddr *)&lsin6, sizeof(lsin6), laddr, sizeof(laddr), NULL, 0, NI_NUMERICHOST);
                    lsin6.sin6_addr  = (struct in6_addr)socketInfo.psi.soi_proto.pri_in.insi_faddr.ina_6;
                    getnameinfo((struct sockaddr *)&lsin6, sizeof(lsin6), faddr, sizeof(faddr), NULL, 0, NI_NUMERICHOST);
                    break;
                }
                case AF_INET: {
                    struct sockaddr_in lsin = {0};
                    lsin.sin_family = AF_INET;
                    lsin.sin_addr = (struct in_addr)socketInfo.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4;
                    getnameinfo((struct sockaddr *)&lsin, sizeof(lsin), laddr, sizeof(laddr), NULL, 0, NI_NUMERICHOST);
                    lsin.sin_addr = (struct in_addr)socketInfo.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4;
                    getnameinfo((struct sockaddr *)&lsin, sizeof(lsin), faddr, sizeof(faddr), NULL, 0, NI_NUMERICHOST);
                    break;
                }
                default:
                    continue;
            }

            char protocol[5];
            snprintf(protocol, 5, "%s%c",
                socketInfo.psi.soi_kind == SOCKINFO_TCP ? "tcp" : "udp",
                socketInfo.psi.soi_family == AF_INET6 ? '6' : '\0');


            int localPort = (int)ntohs(socketInfo.psi.soi_proto.pri_in.insi_lport);
            int remotePort = (int)ntohs(socketInfo.psi.soi_proto.pri_in.insi_fport);

            entry_data = init_port_data_entry();

            os_strdup(protocol, entry_data->protocol);

            os_strdup(laddr, entry_data->local_ip);
            entry_data->local_port = localPort;
            os_strdup(faddr, entry_data->remote_ip);
            entry_data->remote_port = remotePort;

            entry_data->pid = pid;
            os_strdup(pbsd.pbi_name, entry_data->process);

            if (!strncmp(protocol, "tcp", 3)) {
                char *port_state = get_port_state((int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_state);
                os_strdup(port_state, entry_data->state);
                if (strcmp(port_state, "listening") && !check_all) {
                    os_free(port_state);
                    free_port_data(entry_data);
                    continue;
                }
                os_free(port_state);
            }

            // Check if it is necessary to create a port event
            char * string = NULL;
            if (string = analyze_port(entry_data, timestamp), string) {
                mtdebug2(WM_SYS_LOGTAG, "sys_ports_mac() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
                free(string);
            }
        }

        os_free(procFDInfo);
    }

    os_free(pids);
    os_free(timestamp);

    // Checking for closed ports
    check_closed_ports();
}

void sys_proc_mac(int queue_fd, const char* LOCATION){

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    time_t now = time(NULL);
    struct tm localtm;
    localtime_r(&now, &localtm);

    char *timestamp = w_get_timestamp(time(NULL));

    mtdebug1(WM_SYS_LOGTAG, "Starting running processes inventory.");


    int32_t maxproc;
    size_t len = sizeof(maxproc);
    sysctlbyname("kern.maxproc", &maxproc, &len, NULL, 0);

    pid_t *pids = NULL;
    os_calloc(maxproc, 1, pids);
    int count = proc_listallpids(pids, maxproc);

    mtdebug2(WM_SYS_LOGTAG, "Number of processes retrieved: %d", count);

    int index;
    for(index=0; index < count; ++index) {
        pid_t pid;
        struct proc_taskallinfo task_info;

        process_entry_data * entry_data = NULL;

        pid = pids[index];
        int st = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &task_info, PROC_PIDTASKALLINFO_SIZE);

        if(st != PROC_PIDTASKALLINFO_SIZE) {
            mterror(WM_SYS_LOGTAG, "Cannot get process info for PID %d", pid);
            continue;
        }

        /*
            I : Idle
            R : Running
            S : Sleep
            T : Stopped
            Z : Zombie
            E : Internal error getting the status
        */
        char *status;
        switch(task_info.pbsd.pbi_status){
            case 1:
                status = "I";
                break;
            case 2:
                status = "R";
                break;
            case 3:
                status = "S";
                break;
            case 4:
                status = "T";
                break;
            case 5:
                status = "Z";
                break;
            default:
                mtdebug1(WM_SYS_LOGTAG, "Error getting the status of the process %d", pid);
                status = "E";
        }

        entry_data = init_process_data_entry();

        entry_data->pid = pid;
        entry_data->ppid = task_info.pbsd.pbi_ppid;

        os_strdup(task_info.pbsd.pbi_name, entry_data->name);
        os_strdup(status, entry_data->state);

        struct passwd *euser = getpwuid((int)task_info.pbsd.pbi_uid);
        if(euser) {
            os_strdup(euser->pw_name, entry_data->euser);
        }

        struct passwd *ruser = getpwuid((int)task_info.pbsd.pbi_ruid);
        if(ruser) {
            os_strdup(ruser->pw_name, entry_data->ruser);
        }

        struct group *rgroup = getgrgid((int)task_info.pbsd.pbi_rgid);
        if(rgroup) {
            os_strdup(rgroup->gr_name, entry_data->rgroup);
        }

        entry_data->priority = task_info.ptinfo.pti_priority;
        entry_data->nice = task_info.pbsd.pbi_nice;

        entry_data->vm_size = task_info.ptinfo.pti_virtual_size / 1024;

        // Check if it is necessary to create a process event
        char * string = NULL;
        if (string = analyze_process(entry_data, timestamp), string) {
            mtdebug2(WM_SYS_LOGTAG, "sys_proc_mac() sending '%s'", string);
            wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
            free(string);
        }
    }
    os_free(pids);
    os_free(timestamp);

    // Checking for terminated processes
    check_terminated_processes();
}

#endif

#endif /* __BSD__ */
