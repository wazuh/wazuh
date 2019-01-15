/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "version_op.h"

#ifdef __linux__
#include <sched.h>
#elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif

#ifdef WIN32

os_info *get_win_version()
{
    os_info *info;
    unsigned int i;
    char temp[1024];
    DWORD dwRet;
    HKEY RegistryKey;
    char * subkey;
    const DWORD vsize = 1024;
    TCHAR value[vsize];
    DWORD dwCount = vsize;
    char arch[64] = "";
    char nodename[1024] = "";
    char version[64] = "";
    const DWORD size = 30;

    size_t ver_length = 60;
    size_t v_length = 20;

    os_calloc(1,sizeof(os_info),info);
    os_calloc(vsize, sizeof(char), subkey);

    typedef void (WINAPI * PGNSI)(LPSYSTEM_INFO);

    OSVERSIONINFOEX osvi;
    BOOL bOsVersionInfoEx;

    SYSTEM_INFO si;
    PGNSI pGNSI;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi))) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *)&osvi)) {
            return (NULL);
        }
    }

    // Release version
    snprintf(version, 63, "%i.%i", (int)osvi.dwMajorVersion, (int)osvi.dwMinorVersion);
    info->version = strdup(version);

    if (osvi.dwMajorVersion == 6) {

        // Read Windows Version from registry

        snprintf(subkey, vsize - 1, "%s", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
            merror(SK_REG_OPEN, subkey);
            info->os_name = strdup("Microsoft Windows undefined version");
        }
        else {
            dwRet = RegQueryValueEx(RegistryKey, TEXT("ProductName"), NULL, NULL, (LPBYTE)value, &dwCount);
            if (dwRet != ERROR_SUCCESS) {
                merror("Error reading 'ProductName' from Windows registry. (Error %u)",(unsigned int)dwRet);
                info->os_name = strdup("Microsoft Windows undefined version");
            }
            else {
                memset(temp, '\0', sizeof(temp));
                strcpy(temp, "Microsoft ");
                strncat(temp, value, 1022);
                info->os_name = strdup(temp);
            }
            RegCloseKey(RegistryKey);
        }

        // Read Windows Version number from registry
        char vn_temp[64];
        memset(vn_temp, '\0', 64);
        TCHAR winver[size];
        TCHAR wincomp[size];
        DWORD winMajor = 0;
        DWORD winMinor = 0;
        dwCount = size;
        unsigned long type=REG_DWORD;

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
            merror(SK_REG_OPEN, subkey);
        }

        // Windows 10
        dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentMajorVersionNumber"), NULL, &type, (LPBYTE)&winMajor, &dwCount);
        if (dwRet == ERROR_SUCCESS) {
            dwCount = size;
            dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentMinorVersionNumber"), NULL, &type, (LPBYTE)&winMinor, &dwCount);
            if (dwRet != ERROR_SUCCESS) {
                merror("Error reading 'CurrentMinorVersionNumber' from Windows registry. (Error %u)",(unsigned int)dwRet);
            }
            else {
                snprintf(vn_temp, 63, "%d", (unsigned int)winMajor);
                info->os_major = strdup(vn_temp);
                snprintf(vn_temp, 63, "%d", (unsigned int)winMinor);
                info->os_minor = strdup(vn_temp);
                dwCount = size;
                dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentBuildNumber"), NULL, NULL, (LPBYTE)wincomp, &dwCount);
                if (dwRet != ERROR_SUCCESS) {
                    merror("Error reading 'CurrentBuildNumber' from Windows registry. (Error %u)",(unsigned int)dwRet);
                }
                else {
                    snprintf(vn_temp, 63, "%s", wincomp);
                    info->os_build = strdup(vn_temp);
                }
            }
            RegCloseKey(RegistryKey);
        }
        // Windows 6.2 or 6.3
        else {
            dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentVersion"), NULL, NULL, (LPBYTE)winver, &dwCount);
            if (dwRet != ERROR_SUCCESS) {
                merror("Error reading 'Current Version' from Windows registry. (Error %u)",(unsigned int)dwRet);
            }
            else {
                char ** parts = OS_StrBreak('.', winver, 2);
                info->os_major = strdup(parts[0]);
                info->os_minor = strdup(parts[1]);
                for (i = 0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);
                dwCount = size;
                dwRet = RegQueryValueEx(RegistryKey, TEXT("CurrentBuildNumber"), NULL, NULL, (LPBYTE)wincomp, &dwCount);
                if (dwRet != ERROR_SUCCESS) {
                    merror("Error reading 'CurrentBuildNumber' from Windows registry. (Error %u)",(unsigned int)dwRet);
                }
                else {
                    snprintf(vn_temp, 63, "%s", wincomp);
                    info->os_build = strdup(vn_temp);
                }
                RegCloseKey(RegistryKey);
            }
        }

        snprintf(version, 63, "%s.%s.%s", info->os_major, info->os_minor, info->os_build);
        info->os_version = strdup(version);
    }
    else {
        if (osvi.dwMajorVersion == 5) {
            if (osvi.dwMinorVersion == 0) {
                info->os_name = strdup("Microsoft Windows 2000");
            }
            else if (osvi.dwMinorVersion == 1) {
                info->os_name = strdup("Microsoft Windows XP");
            }
            else if (osvi.dwMinorVersion == 2) {
                pGNSI = (PGNSI) GetProcAddress(GetModuleHandle("kernel32.dll"),"GetNativeSystemInfo");
                if (NULL != pGNSI) {
                    pGNSI(&si);
                }
                if (osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                    info->os_name = strdup("Microsoft Windows XP Professional x64 Edition");
                }
                else {
                    if ( GetSystemMetrics(89) != 0 ) {
                        info->os_name = strdup("Microsoft Windows Server 2003 R2");
                    }
                    else {
                        info->os_name = strdup("Microsoft Windows Server 2003");
                    }
                }
            }
        } else if (osvi.dwMajorVersion == 4) {
            switch (osvi.dwPlatformId) {
                case VER_PLATFORM_WIN32_NT:
                    info->os_name = strdup("Microsoft Windows NT");
                    break;

                case VER_PLATFORM_WIN32_WINDOWS:
                    if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0) {
                        info->os_name = strdup("Microsoft Windows 95");
                    }
                    if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10) {
                        info->os_name = strdup("Microsoft Windows 98");
                    }
                    if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90) {
                        info->os_name = strdup("Microsoft Windows ME");
                    }
                    break;
            }
        }
        else {
            info->os_name = strdup("Microsoft Windows");
        }

        os_calloc(ver_length + 1, sizeof(char), info->os_version);
        os_calloc(v_length + 1, sizeof(char), info->os_major);
        os_calloc(v_length + 1, sizeof(char), info->os_minor);
        os_calloc(v_length + 1, sizeof(char), info->os_build);

        snprintf(info->os_major, v_length, "%i",(int)osvi.dwMajorVersion);
        snprintf(info->os_minor, v_length, "%i",(int)osvi.dwMinorVersion);
        snprintf(info->os_build, v_length, "%d",(int)osvi.dwBuildNumber & 0xFFFF);
        snprintf(info->os_version, ver_length, "%i.%i.%d",
                 (int)osvi.dwMajorVersion,
                 (int)osvi.dwMinorVersion,
                 (int)osvi.dwBuildNumber & 0xFFFF );

    }

    // Read Architecture

    snprintf(subkey, vsize - 1, "%s", "System\\CurrentControlSet\\Control\\Session Manager\\Environment");

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
        merror(SK_REG_OPEN, subkey);
        info->machine = strdup("unknown");
    } else {
        dwCount = vsize;
        dwRet = RegQueryValueEx(RegistryKey, TEXT("PROCESSOR_ARCHITECTURE"), NULL, NULL, (LPBYTE)&arch, &dwCount);

        if (dwRet != ERROR_SUCCESS) {
            merror("Error reading 'Architecture' from Windows registry. (Error %u)",(unsigned int)dwRet);
            info->machine = strdup("unknown");
        } else {

            if (!strncmp(arch, "AMD64", 5) || !strncmp(arch, "IA64", 4)) {
                info->machine = strdup("x86_64");
            } else if (!strncmp(arch, "x86", 3)) {
                info->machine = strdup("i686");
            } else {
                info->machine = strdup("unknown");
            }

        }
        RegCloseKey(RegistryKey);
    }

    // Read Hostname

    snprintf(subkey, vsize - 1, "%s", "System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
        merror(SK_REG_OPEN, subkey);
        info->nodename = strdup("unknown");
    } else {
        dwCount = size;
        dwRet = RegQueryValueEx(RegistryKey, TEXT("ComputerName"), NULL, NULL, (LPBYTE)&nodename, &dwCount);

        if (dwRet != ERROR_SUCCESS) {
            merror("Error reading 'hostname' from Windows registry. (Error %u)",(unsigned int)dwRet);
            info->nodename = strdup("unknown");
        } else {
            info->nodename = strdup(nodename);
        }
        RegCloseKey(RegistryKey);
    }

    free(subkey);

    return info;
}

#else

char *OSX_ReleaseName(const int version) {
    char *r_names[] = {
    /* 10 */ "Snow Leopard",
    /* 11 */ "Lion",
    /* 12 */ "Mountain Lion",
    /* 13 */ "Mavericks",
    /* 14 */ "Yosemite",
    /* 15 */ "El Capitan",
    /* 16 */ "Sierra",
    /* 17 */ "High Sierra",
    /* 18 */ "Mojave"};
    if (version >= 10 && version <= 18)
        return r_names[version%10];
    else
        return "Unknown";
}

os_info *get_unix_version()
{
    FILE *os_release, *cmd_output, *version_release, *cmd_output_ver;
    char buff[256];
    char *tag, *end;
    char *name = NULL;
    char *id = NULL;
    char *version = NULL;
    char *codename = NULL;
    regmatch_t match[2];
    int match_size;
    struct utsname uts_buf;
    os_info *info;

    os_calloc(1,sizeof(os_info),info);

    // Try to open /etc/os-release
    os_release = fopen("/etc/os-release", "r");
    // Try to open /usr/lib/os-release
    if (!os_release) os_release = fopen("/usr/lib/os-release", "r");

    if (os_release) {
        while (fgets(buff, sizeof(buff)- 1, os_release)) {
            tag = strtok(buff, "=");
            if (strcmp (tag,"NAME") == 0){
                if (!name) {
                    name = strtok(NULL, "\n");
                    if (name[0] == '\"' && (end = strchr(++name, '\"'), end)) {
                        *end = '\0';
                    }
                    info->os_name = strdup(name);
                }
            } else if (strcmp (tag,"VERSION") == 0) {
                if (!version) {
                    version = strtok(NULL, "\n");
                    if (version[0] == '\"' && (end = strchr(++version, '\"'), end)) {
                        *end = '\0';
                    }
                    info->os_version = strdup(version);
                }
            } else if (strcmp (tag,"ID") == 0){
                if (!id) {
                    id = strtok(NULL, " \n");
                    if (id[0] == '\"' && (end = strchr(++id, '\"'), end)) {
                        *end = '\0';
                    }
                    info->os_platform = strdup(id);
                }
            }
        }
        fclose(os_release);
    }
    // Linux old distributions without 'os-release' file
    else {
        regex_t regexCompiled;
        regmatch_t match[2];
        int match_size;
        // CentOS
        if (version_release = fopen("/etc/centos-release","r"), version_release){
            info->os_name = strdup("CentOS Linux");
            info->os_platform = strdup("centos");
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Can not compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Fedora
        } else if (version_release = fopen("/etc/fedora-release","r"), version_release){
            info->os_name = strdup("Fedora");
            info->os_platform = strdup("fedora");
            static const char *pattern = " ([0-9][0-9]*) ";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Can not compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf(info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // RedHat
        } else if (version_release = fopen("/etc/redhat-release","r"), version_release){
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Can not compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if (strstr(buff, "CentOS")){
                        info->os_name = strdup("CentOS Linux");
                        info->os_platform = strdup("centos");
                } else if (strstr(buff, "Fedora")){
                        info->os_name = strdup("Fedora");
                        info->os_platform = strdup("fedora");
                } else {
                    if (strstr(buff, "Server")){
                        info->os_name = strdup("Red Hat Enterprise Linux Server");
                    } else {
                        info->os_name = strdup("Red Hat Enterprise Linux");
                    }
                    info->os_platform = strdup("rhel");
                }

                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Ubuntu
        } else if (version_release = fopen("/etc/lsb-release","r"), version_release){
            info->os_name = strdup("Ubuntu");
            info->os_platform = strdup("ubuntu");
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                tag = strtok(buff, "=");
                if (strcmp(tag,"DISTRIB_RELEASE") == 0){
                    info->os_version = strdup(strtok(NULL, "\n"));
                    break;
                }
            }

            fclose(version_release);
        // Gentoo
        } else if (version_release = fopen("/etc/gentoo-release","r"), version_release){
            info->os_name = strdup("Gentoo");
            info->os_platform = strdup("gentoo");
            static const char *pattern = " ([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // SuSE
        } else if (version_release = fopen("/etc/SuSE-release","r"), version_release){
            info->os_name = strdup("SuSE Linux");
            info->os_platform = strdup("suse");
            static const char *pattern = ".*VERSION = ([0-9][0-9]*)";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Arch
        } else if (version_release = fopen("/etc/arch-release","r"), version_release){
            info->os_name = strdup("Arch Linux");
            info->os_platform = strdup("arch");
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Debian
        } else if (version_release = fopen("/etc/debian_version","r"), version_release){
            info->os_name = strdup("Debian GNU/Linux");
            info->os_platform = strdup("debian");
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Slackware
        } else if (version_release = fopen("/etc/slackware-version","r"), version_release){
            info->os_name = strdup("Slackware");
            info->os_platform = strdup("slackware");
            static const char *pattern = " ([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    info->os_version = malloc(match_size +1);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        } else if (cmd_output = popen("uname", "r"), cmd_output) {
            if(fgets(buff,sizeof(buff) - 1, cmd_output) == NULL){
                mdebug1("Cannot read from command output (uname).");
            // MacOSX
            } else if(strcmp(strtok(buff, "\n"),"Darwin") == 0){
                info->os_platform = strdup("darwin");
                if (cmd_output_ver = popen("sw_vers -productName", "r"), cmd_output_ver) {
                    if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                        mdebug1("Cannot read from command output (sw_vers -productName).");
                    } else {
                        info->os_name = strdup(strtok(buff, "\n"));
                    }
                    pclose(cmd_output_ver);
                }
                if (cmd_output_ver = popen("sw_vers -productVersion", "r"), cmd_output_ver) {
                    if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                        mdebug1("Cannot read from command output (sw_vers -productVersion).");
                    } else {
                        info->os_version = strdup(strtok(buff, "\n"));
                    }
                    pclose(cmd_output_ver);
                }
                if (cmd_output_ver = popen("sw_vers -buildVersion", "r"), cmd_output_ver) {
                    if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                        mdebug1("Cannot read from command output (sw_vers -buildVersion).");
                    } else {
                        info->os_build = strdup(strtok(buff, "\n"));
                    }
                    pclose(cmd_output_ver);
                }
                if (cmd_output_ver = popen("uname -r", "r"), cmd_output_ver) {
                    if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                        mdebug1("Cannot read from command output (uname -r).");
                    } else if (w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", buff, 2, match)){
                        match_size = match[1].rm_eo - match[1].rm_so;
                        char *kern = NULL;
                        kern = malloc(match_size +1);
                        snprintf(kern, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                        info->os_codename = strdup(OSX_ReleaseName(atoi(kern)));
                        free(kern);
                    }
                    pclose(cmd_output_ver);
                }
            } else if (strcmp(strtok(buff, "\n"),"SunOS") == 0){ // Sun OS
                info->os_name = strdup("SunOS");
                info->os_platform = strdup("sunos");

                if (os_release = fopen("/etc/release", "r"), os_release) {
                  if(fgets(buff, sizeof(buff) - 1, os_release) == NULL){
                      merror("Cannot read from /etc/release.");
                      fclose(os_release);
                      pclose(cmd_output);
                      goto free_os_info;
                  } else {
                      char *base;
                      char *found;
                      char tag[] = "Oracle Solaris";
                      if (found = strstr(buff, tag), found) {
                          for (found += strlen(tag); *found != '\0' && *found == ' '; found++);
                          for (base = found; *found != '\0' && *found != ' '; found++);
                          *found = '\0';
                          os_strdup(base, info->os_version);
                          fclose(os_release);
                      } else {
                          merror("Cannot get the Solaris version.");
                          fclose(os_release);
                          pclose(cmd_output);
                          goto free_os_info;
                      }
                  }
                } else {
                    pclose(cmd_output);
                  goto free_os_info;
                }
            } else if (strcmp(strtok(buff, "\n"),"HP-UX") == 0){ // HP-UX
                info->os_name = strdup("HP-UX");
                info->os_platform = strdup("hp-ux");
                if (cmd_output_ver = popen("uname -r", "r"), cmd_output_ver) {
                    if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                        mdebug1("Cannot read from command output (uname -r).");
                    } else if (w_regexec("B\\.([0-9][0-9]*\\.[0-9]*)", buff, 2, match)){
                        match_size = match[1].rm_eo - match[1].rm_so;
                        info->os_version = malloc(match_size +1);
                        snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    }
                    pclose(cmd_output_ver);
                }
            } else if (strcmp(strtok(buff, "\n"),"OpenBSD") == 0 ||
                       strcmp(strtok(buff, "\n"),"NetBSD")  == 0 ||
                       strcmp(strtok(buff, "\n"),"FreeBSD") == 0 ){ // BSD
                info->os_name = strdup("BSD");
                info->os_platform = strdup("bsd");
                if (cmd_output_ver = popen("uname -r", "r"), cmd_output_ver) {
                    if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                        mdebug1("Cannot read from command output (uname -r).");
                    } else if (w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", buff, 2, match)){
                        match_size = match[1].rm_eo - match[1].rm_so;
                        info->os_version = malloc(match_size +1);
                        snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    }
                    pclose(cmd_output_ver);
                }
            } else if (strcmp(strtok(buff, "\n"),"Linux") == 0){ // Linux undefined
                info->os_name = strdup("Linux");
                info->os_platform = strdup("linux");
            }
            pclose(cmd_output);
        }
    }

    if (uname(&uts_buf) >= 0) {
        os_strdup(uts_buf.sysname, info->sysname);
        os_strdup(uts_buf.nodename, info->nodename);
        os_strdup(uts_buf.release, info->release);
        os_strdup(uts_buf.version, info->version);
        os_strdup(uts_buf.machine, info->machine);
    } else {
        goto free_os_info;
    }

    if (info->os_version) { // Parsing version
        // os_major.os_minor (os_codename)
        os_strdup(info->os_version, version);
        if (codename = strstr(version, " ("), codename){
            *codename = '\0';
            codename += 2;
            *(codename + strlen(codename) - 1) = '\0';
            info->os_codename = strdup(codename);
        }
        free(version);
        // Get os_major
        if (w_regexec("^([0-9]+)\\.*", info->os_version, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            info->os_major = malloc(match_size +1);
            snprintf(info->os_major, match_size + 1, "%.*s", match_size, info->os_version + match[1].rm_so);
        }
        // Get os_minor
        if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", info->os_version, 2, match)) {
            match_size = match[1].rm_eo - match[1].rm_so;
            info->os_minor = malloc(match_size +1);
            snprintf(info->os_minor, match_size + 1, "%.*s", match_size, info->os_version + match[1].rm_so);
        }
        // Get OSX codename
        if (strcmp(info->os_platform,"darwin") == 0) {
            if (info->os_codename) {
                size_t len = 4;
                len += strlen(info->os_version);
                len += strlen(info->os_codename);
                os_realloc(info->os_version, len, info->os_version);
                snprintf(info->os_version, len, "%s (%s)", info->os_version, info->os_codename);
            }
        }
    } else {
        // Empty version
        info->os_version = strdup("0.0");
    }

    return info;
free_os_info:
    free_osinfo(info);
    return NULL;
}

#endif /* WIN32 */

void free_osinfo(os_info * osinfo) {
    if (osinfo) {
        free(osinfo->os_name);
        free(osinfo->os_major);
        free(osinfo->os_minor);
        free(osinfo->os_build);
        free(osinfo->os_version);
        free(osinfo->os_codename);
        free(osinfo->os_platform);
        free(osinfo->sysname);
        free(osinfo->nodename);
        free(osinfo->release);
        free(osinfo->version);
        free(osinfo->machine);
        free(osinfo);
    }
}

// Get number of processors
// Returns 1 on error

int get_nproc() {
#ifdef __linux__
    #ifdef CPU_COUNT
    cpu_set_t set;
    CPU_ZERO(&set);

    if (sched_getaffinity(getpid(), sizeof(set), &set) < 0) {
        mwarn("sched_getaffinity(): %s (%d).", strerror(errno), errno);
        return 1;
    }

    return CPU_COUNT(&set);
    #else
    FILE *fp;
    char string[OS_MAXSTR];
    int cpu_cores = 0;

    if (!(fp = fopen("/proc/cpuinfo", "r"))) {
        mwarn("Unable to read cpuinfo file");
    } else {
        while (fgets(string, OS_MAXSTR, fp) != NULL){
            if (!strncmp(string, "processor", 9)){
                cpu_cores++;
            }
        }
        fclose(fp);
    }
    
    if(!cpu_cores)
        cpu_cores = 1;

    return cpu_cores;
    #endif
#elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    unsigned int cpu_cores;
    int mib[] = { CTL_HW, HW_NCPU };
    size_t len = sizeof(cpu_cores);

    if (!sysctl(mib, 2, &cpu_cores, &len, NULL, 0)) {
        return cpu_cores;
    } else {
        mwarn("sysctl failed getting CPU cores: %s (%d)", strerror(errno), errno);
        return 1;
    }
#else
    mwarn("get_nproc(): Unimplemented.");
    return 1;
#endif
}
