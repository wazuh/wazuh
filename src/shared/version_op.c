/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
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

char *get_release_from_build(char *os_build);

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
    char version[64] = "";
    const DWORD size = 30;
    unsigned long type = REG_DWORD;

    size_t ver_length = 60;
    size_t v_length = 20;

    os_calloc(1,sizeof(os_info),info);
    os_calloc(vsize, sizeof(char), subkey);

    typedef void (WINAPI * PGNSI)(LPSYSTEM_INFO);

    OSVERSIONINFOEX osvi;
    BOOL bOsVersionInfoEx;

    SYSTEM_INFO si = {0};
    PGNSI pGNSI;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi), !bOsVersionInfoEx) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *)&osvi)) {
            free(info);
            free(subkey);
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

            dwCount = vsize;
            dwRet = RegQueryValueEx(RegistryKey, TEXT("ReleaseId"), NULL, NULL, (LPBYTE)value, &dwCount);
            if (dwRet != ERROR_SUCCESS) {
                mdebug1("Could not read the 'ReleaseId' key from Windows registry. (Error %u)",(unsigned int)dwRet);
                info->os_release = get_release_from_build(info->os_build);
            }
            else {
                info->os_release = strdup(value);
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
                pGNSI = (PGNSI)(LPSYSTEM_INFO)GetProcAddress(GetModuleHandle("kernel32.dll"),"GetNativeSystemInfo");
                if (NULL != pGNSI) {
                    pGNSI(&si);
                } else {
                    mwarn("It was not possible to retrieve GetNativeSystemInfo from kernek32.dll");
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

    // Read Service Pack
    if(!info->os_release) {
        DWORD service_pack = 0;
        dwCount = sizeof(DWORD);
        snprintf(subkey, vsize - 1, "%s", "SYSTEM\\CurrentControlSet\\Control\\Windows");

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
            merror(SK_REG_OPEN, subkey);
        }
        else {
            dwRet = RegQueryValueEx(RegistryKey, TEXT("CSDVersion"), NULL, &type, (LPBYTE)&service_pack, &dwCount);
            if (dwRet != ERROR_SUCCESS) {
                merror("Error reading 'CSDVersion' from Windows registry. (Error %u)",(unsigned int)dwRet);
            }
            else {
                switch(service_pack) {
                case 256:
                    info->os_release = strdup("sp1");
                    break;
                case 512:
                    info->os_release = strdup("sp2");
                    break;
                case 768:
                    info->os_release = strdup("sp3");
                    break;
                case 1024:
                    info->os_release = strdup("sp4");
                    break;
                case 1280:
                    info->os_release = strdup("sp5");
                    break;
                case 1536:
                    info->os_release = strdup("sp6");
                    break;
                default:
                    mdebug2("The value of CSDVersion is not a recognizable service pack.: %lu.", service_pack);
                }
            }
            RegCloseKey(RegistryKey);
        }
    }

    // Read Architecture

    snprintf(subkey, vsize - 1, "%s", "System\\CurrentControlSet\\Control\\Session Manager\\Environment");

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
        merror(SK_REG_OPEN, subkey);
    } else {
        char arch[64] = "";
        dwCount = sizeof(arch);
        dwRet = RegQueryValueEx(RegistryKey, TEXT("PROCESSOR_ARCHITECTURE"), NULL, NULL, (LPBYTE)&arch, &dwCount);

        if (dwRet != ERROR_SUCCESS) {
            merror("Error reading 'Architecture' from Windows registry. (Error %u)",(unsigned int)dwRet);
        } else {
            if (!strncmp(arch, "AMD64", 5) || !strncmp(arch, "IA64", 4) || !strncmp(arch, "ARM64", 5)) {
                info->machine = strdup("x86_64");
            } else if (!strncmp(arch, "x86", 3)) {
                info->machine = strdup("i686");
            }
        }
        RegCloseKey(RegistryKey);
    }

    if (!info->machine) {
        info->machine = strdup("unknown");
    }

    // Read Hostname

    snprintf(subkey, vsize - 1, "%s", "System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");
    char nodename[1024] = "";
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
        merror(SK_REG_OPEN, subkey);
    } else {
        dwCount = size;
        dwRet = RegQueryValueEx(RegistryKey, TEXT("ComputerName"), NULL, NULL, (LPBYTE)&nodename, &dwCount);

        if (dwRet != ERROR_SUCCESS) {
            merror("Error reading 'hostname' from Windows registry. (Error %u)",(unsigned int)dwRet);
        } else {
            info->nodename = strdup(nodename);
        }
        RegCloseKey(RegistryKey);
    }

    if (!info->nodename) {
        info->nodename = strdup("unknown");
    }

    free(subkey);

    return info;
}

char *get_release_from_build(char *os_build) {
    char *retval = NULL;

    if (os_build) {
        if (!strcmp(os_build, "10240")) {
            os_strdup("1507", retval);
        } else if (!strcmp(os_build, "10586")) {
            os_strdup("1511", retval);
        } else if (!strcmp(os_build, "14393")) {
            os_strdup("1607", retval);
        } else if (!strcmp(os_build, "15063")) {
            os_strdup("1709", retval);
        } else if (!strcmp(os_build, "17134")) {
            os_strdup("1803", retval);
        } else if (!strcmp(os_build, "17763")) {
            os_strdup("1809", retval);
        } else if (!strcmp(os_build, "18362")) {
            os_strdup("1903", retval);
        } else if (!strcmp(os_build, "18363")) {
            os_strdup("1909", retval);
        } else {
            mdebug1("The release associated with the %s build is not recognized.", os_build);
        }
    }

    return retval;
}

#else

const char *OSX_ReleaseName(int version) {
    const char *R_NAMES[] = {
    /* 10 */ "Snow Leopard",
    /* 11 */ "Lion",
    /* 12 */ "Mountain Lion",
    /* 13 */ "Mavericks",
    /* 14 */ "Yosemite",
    /* 15 */ "El Capitan",
    /* 16 */ "Sierra",
    /* 17 */ "High Sierra",
    /* 18 */ "Mojave",
    /* 19 */ "Catalina",
    /* 20 */ "Big Sur",
    /* 21 */ "Monterey",
    /* 22 */ "Ventura",
    /* 23 */ "Sonoma",
    };

    version -= 10;

    if (version >= 0 && (unsigned)version < sizeof(R_NAMES) / sizeof(char *)) {
        return R_NAMES[version];
    } else {
        return "Unknown";
    }
}


os_info *get_unix_version()
{
    FILE *os_release, *cmd_output, *version_release, *cmd_output_ver;
    char buff[OS_SIZE_256];
    char *tag, *end;
    char *name = NULL;
    char *id = NULL;
    char *version = NULL;
    char *version_id = NULL;
    char *codename = NULL;
    char *save_ptr = NULL;
    regmatch_t match[2];
    int match_size;
    struct utsname uts_buf;
    os_info *info;

    os_calloc(1,sizeof(os_info),info);

    // Try to open /etc/os-release
    os_release = wfopen("/etc/os-release", "r");
    // Try to open /usr/lib/os-release
    if (!os_release) os_release = wfopen("/usr/lib/os-release", "r");

    if (os_release) {
        while (fgets(buff, sizeof(buff)- 1, os_release)) {
            tag = strtok_r(buff, "=", &save_ptr);
            if (tag) {
                if (strcmp (tag,"NAME") == 0) {
                    if (!name) {
                        name = strtok_r(NULL, "\n", &save_ptr);
                        if (name[0] == '\"' && (end = strchr(++name, '\"'), end)) {
                            *end = '\0';
                        }
                        info->os_name = strdup(name);
                    }
                } else if (strcmp (tag,"VERSION") == 0) {
                    if (!version) {
                        if (version_id) {
                            os_free(info->os_version);
                        }
                        version = strtok_r(NULL, "\n", &save_ptr);
                        if (version[0] == '\"' && (end = strchr(++version, '\"'), end)) {
                            *end = '\0';
                        }
                        info->os_version = strdup(version);
                    }
                } else if (strcmp (tag,"VERSION_ID") == 0) {
                    if (!version && !version_id) {
                        version_id = strtok_r(NULL, "\n", &save_ptr);
                        if (version_id[0] == '\"' && (end = strchr(++version_id, '\"'), end)) {
                            *end = '\0';
                        }
                        info->os_version = strdup(version_id);
                    }
                } else if (strcmp (tag,"ID") == 0) {
                    if (!id) {
                        id = strtok_r(NULL, " \n", &save_ptr);
                        if (id[0] == '\"' && (end = strchr(++id, '\"'), end)) {
                            *end = '\0';
                        }
                        info->os_platform = strdup(id);
                    }
                }
            }
        }
        fclose(os_release);

        // If the OS is CentOS, try to get the version from the 'centos-release' file.
        // If the OS is Arch Linux, openSUSE Tumbleweed set os_version as empty string.
        if (info->os_platform) {
            if (strcmp(info->os_platform, "centos") == 0) {
                regex_t regexCompiled;
                regmatch_t match[2];
                int match_size;
                if (version_release = wfopen("/etc/centos-release","r"), version_release){
                    os_free(info->os_version);
                    static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
                    if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                        merror_exit("Cannot compile regular expression.");
                    }
                    while (fgets(buff, sizeof(buff) - 1, version_release)) {
                        if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                            match_size = match[1].rm_eo - match[1].rm_so;
                            os_malloc(match_size + 1, info->os_version);
                            snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                            break;
                        }
                    }
                    regfree(&regexCompiled);
                    fclose(version_release);
                }
            } else if (strcmp(info->os_platform, "opensuse-tumbleweed") == 0 ||
                          strcmp(info->os_platform, "arch") == 0) {
                os_free(info->os_version);
                os_strdup("", info->os_version);
            }
        }
    }

    if (!info->os_name || (!info->os_version && !info->os_build) || !info->os_platform) {
        os_free(info->os_name);
        os_free(info->os_version);
        os_free(info->os_platform);
        os_free(info->os_build);
        regex_t regexCompiled;
        regmatch_t match[4];
        int match_size;

        // CentOS
        if (version_release = wfopen("/etc/centos-release","r"), version_release){
            info->os_name = strdup("CentOS Linux");
            info->os_platform = strdup("centos");
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Can not compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Fedora
        } else if (version_release = wfopen("/etc/fedora-release","r"), version_release){
            info->os_name = strdup("Fedora");
            info->os_platform = strdup("fedora");
            static const char *pattern = " ([0-9][0-9]*) ";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Can not compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf(info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // RedHat
        } else if (version_release = wfopen("/etc/redhat-release","r"), version_release){
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
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Arch
        } else if (version_release = wfopen("/etc/arch-release","r"), version_release){
            info->os_name = strdup("Arch Linux");
            info->os_platform = strdup("arch");
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            if (info->os_version == NULL) {
                os_strdup("", info->os_version);
            }

            regfree(&regexCompiled);
            fclose(version_release);
        // Gentoo
        } else if (version_release = wfopen("/etc/gentoo-release","r"), version_release){
            info->os_name = strdup("Gentoo");
            info->os_platform = strdup("gentoo");
            static const char *pattern = " ([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // SuSE
        } else if (version_release = wfopen("/etc/SuSE-release","r"), version_release){
            info->os_name = strdup("SuSE Linux");
            info->os_platform = strdup("suse");
            static const char *pattern = ".*VERSION = ([0-9][0-9]*)";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Ubuntu
        } else if (version_release = wfopen("/etc/lsb-release","r"), version_release){
            info->os_name = strdup("Ubuntu");
            info->os_platform = strdup("ubuntu");
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                tag = strtok_r(buff, "=", &save_ptr);
                if (tag && strcmp(tag,"DISTRIB_RELEASE") == 0){
                    info->os_version = strdup(strtok_r(NULL, "\n", &save_ptr));
                    break;
                }
            }
            fclose(version_release);
        // Debian
        } else if (version_release = wfopen("/etc/debian_version","r"), version_release){
            info->os_name = strdup("Debian GNU/Linux");
            info->os_platform = strdup("debian");
            static const char *pattern = "([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Slackware
        } else if (version_release = wfopen("/etc/slackware-version","r"), version_release){
            info->os_name = strdup("Slackware");
            info->os_platform = strdup("slackware");
            static const char *pattern = " ([0-9][0-9]*\\.?[0-9]*)\\.*";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 2, match, 0) == 0){
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        // Alpine
        } else if (version_release = wfopen("/etc/alpine-release","r"), version_release){
            info->os_name = strdup("Alpine Linux");
            info->os_platform = strdup("alpine");
            static const char *pattern = "([0-9]+\\.)?([0-9]+\\.)?([0-9]+)";
            if (regcomp(&regexCompiled, pattern, REG_EXTENDED)) {
                merror_exit("Cannot compile regular expression.");
            }
            while (fgets(buff, sizeof(buff) - 1, version_release)) {
                if(regexec(&regexCompiled, buff, 4, match, 0) == 0){
                    match_size = match[0].rm_eo - match[0].rm_so;
                    os_malloc(match_size + 1, info->os_version);
                    snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[0].rm_so);
                    break;
                }
            }
            regfree(&regexCompiled);
            fclose(version_release);
        } else {
            char *uname_path = NULL;

            if (get_binary_path("uname", &uname_path) < 0) {
                mdebug1("Binary '%s' not found in default paths, the full path will not be used.", uname_path);
            }

            if (cmd_output = popen(uname_path, "r"), cmd_output) {
                char full_cmd[OS_MAXSTR] = {0};

                if (fgets(buff,sizeof(buff) - 1, cmd_output) == NULL) {
                    mdebug1("Cannot read from command output (uname).");
                // MacOSX
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr),"Darwin") == 0) {
                    char *cmd_path = NULL;
                    info->os_platform = strdup("darwin");

                    if (get_binary_path("system_profiler", &cmd_path) < 0) {
                        mdebug1("Binary '%s' not found in default paths, the full path will not be used.", cmd_path);
                    }

                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd_path, "SPSoftwareDataType");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        while (fgets(buff, sizeof(buff), cmd_output_ver) != NULL) {
                            char *key = strtok_r(buff, ":", &save_ptr);
                            if (key) {
                                const char *expected_key = "System Version";
                                char *trimmed_key = w_strtrim(key);
                                if (NULL != trimmed_key && strncmp(trimmed_key, expected_key, strlen(expected_key)) == 0) {
                                    char *value = strtok_r(NULL, " ", &save_ptr);
                                    if (value) {
                                        w_strdup(value, info->os_name);
                                    } else {
                                        mdebug1("Cannot parse System Version value (system_profiler SPSoftwareDataType).");
                                    }
                                }
                                if(info->os_name) {
                                    break;
                                }
                            }
                        }
                        if (NULL == info->os_name) {
                            mdebug1("Cannot read from command output (system_profiler SPSoftwareDataType).");
                        }
                        pclose(cmd_output_ver);
                    }

                    os_free(cmd_path);
                    if (get_binary_path("sw_vers", &cmd_path) < 0) {
                        mdebug1("Binary '%s' not found in default paths, the full path will not be used.", cmd_path);
                    }

                    memset(full_cmd, '\0', OS_MAXSTR);
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd_path, "-productVersion");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                            mdebug1("Cannot read from command output (sw_vers -productVersion).");
                        } else {
                            w_strdup(strtok_r(buff, "\n", &save_ptr), info->os_version);
                        }
                        pclose(cmd_output_ver);
                    }

                    memset(full_cmd, '\0', OS_MAXSTR);
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd_path, "-buildVersion");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                            mdebug1("Cannot read from command output (sw_vers -buildVersion).");
                        } else {
                            w_strdup(strtok_r(buff, "\n", &save_ptr), info->os_build);
                        }
                        pclose(cmd_output_ver);
                    }

                    memset(full_cmd, '\0', OS_MAXSTR);
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", uname_path, "-r");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                            mdebug1("Cannot read from command output (uname -r).");
                        } else if (w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", buff, 2, match)){
                            match_size = match[1].rm_eo - match[1].rm_so;
                            char *kern = NULL;
                            os_malloc(match_size + 1, kern);
                            snprintf(kern, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                            w_strdup(OSX_ReleaseName(atoi(kern)), info->os_codename);
                            free(kern);
                        }
                        pclose(cmd_output_ver);
                    }
                    os_free(cmd_path);
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr),"SunOS") == 0){ // Sun OS
                    info->os_name = strdup("SunOS");
                    info->os_platform = strdup("sunos");

                    if (os_release = wfopen("/etc/release", "r"), os_release) {
                        if (fgets(buff, sizeof(buff) - 1, os_release) == NULL) {
                            merror("Cannot read from /etc/release.");
                            fclose(os_release);
                            pclose(cmd_output);
                            os_free(uname_path);
                            goto free_os_info;
                        } else {
                            char *base;
                            char tag[]  = "Solaris";
                            char *found = strstr(buff, tag);
                            if (found) {
                                for (found += strlen(tag); *found != '\0' && *found == ' '; found++);
                                for (base = found; *found != '\0' && *found != ' '; found++);
                                *found = '\0';
                                os_strdup(base, info->os_version);
                                fclose(os_release);
                            } else {
                                merror("Cannot get the Solaris version.");
                                fclose(os_release);
                                pclose(cmd_output);
                                os_free(uname_path);
                                goto free_os_info;
                            }
                        }
                    } else {
                        pclose(cmd_output);
                        os_free(uname_path);
                        goto free_os_info;
                    }
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr),"HP-UX") == 0){ // HP-UX
                    info->os_name = strdup("HP-UX");
                    info->os_platform = strdup("hp-ux");

                    memset(full_cmd, '\0', OS_MAXSTR);
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", uname_path, "-r");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                            mdebug1("Cannot read from command output (uname -r).");
                        } else if (w_regexec("B\\.([0-9][0-9]*\\.[0-9]*)", buff, 2, match)){
                            match_size = match[1].rm_eo - match[1].rm_so;
                            os_malloc(match_size + 1, info->os_version);
                            snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                        }
                        pclose(cmd_output_ver);
                    }
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr),"OpenBSD") == 0 ||
                        strcmp(strtok_r(buff, "\n", &save_ptr),"NetBSD")  == 0 ||
                        strcmp(strtok_r(buff, "\n", &save_ptr),"FreeBSD") == 0 ){ // BSD
                    info->os_name = strdup("BSD");
                    info->os_platform = strdup("bsd");

                    memset(full_cmd, '\0', OS_MAXSTR);
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", uname_path, "-r");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                            mdebug1("Cannot read from command output (uname -r).");
                        } else if (w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", buff, 2, match)){
                            match_size = match[1].rm_eo - match[1].rm_so;
                            os_malloc(match_size + 1, info->os_version);
                            snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                        }
                        pclose(cmd_output_ver);
                    }
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr),"ZscalerOS") == 0) {
                    info->os_name = strdup("BSD");
                    info->os_platform = strdup("bsd");

                    memset(full_cmd, '\0', OS_MAXSTR);
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", uname_path, "-r");
                    if (cmd_output_ver = popen(full_cmd, "r"), cmd_output_ver) {
                        if(fgets(buff, sizeof(buff) - 1, cmd_output_ver) == NULL){
                            mdebug1("Cannot read from command output (uname -r).");
                        } else if (w_regexec("([0-9]+-\\S*).*", buff, 2, match)){
                            match_size = match[1].rm_eo - match[1].rm_so;
                            os_malloc(match_size + 1, info->os_version);
                            snprintf (info->os_version, match_size +1, "%.*s", match_size, buff + match[1].rm_so);
                        }
                        pclose(cmd_output_ver);
                    }
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr), "AIX") == 0) { // AIX
                    char *cmd_path = NULL;

                    os_strdup("AIX", info->os_name);
                    os_strdup("aix", info->os_platform);

                    if (get_binary_path("oslevel", &cmd_path) < 0) {
                        mdebug1("Binary '%s' not found in default paths, the full path will not be used.", cmd_path);
                    }

                    if (cmd_output_ver = popen(cmd_path, "r"), cmd_output_ver) {
                        if (fgets(buff, sizeof(buff) - 1, cmd_output_ver)) {
                            int buff_len = strlen(buff);
                            if (buff_len > 0) {
                                buff[buff_len - 1] = '\0';
                                os_strdup(buff, info->os_version);
                            }
                        } else {
                            mdebug1("Cannot read from command output (oslevel).");
                        }
                        pclose(cmd_output_ver);
                    }
                    os_free(cmd_path);
                } else if (strcmp(strtok_r(buff, "\n", &save_ptr), "Linux") == 0) { // Linux undefined
                    info->os_name = strdup("Linux");
                    info->os_platform = strdup("linux");
                }
                pclose(cmd_output);
            }
            os_free(uname_path);
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
        if (strcmp(info->os_version, "") != 0) {
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
                os_malloc(match_size + 1, info->os_major);
                snprintf(info->os_major, match_size + 1, "%.*s", match_size, info->os_version + match[1].rm_so);
            }
            // Get os_minor
            if (w_regexec("^[0-9]+\\.([0-9]+)\\.*", info->os_version, 2, match)) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, info->os_minor);
                snprintf(info->os_minor, match_size + 1, "%.*s", match_size, info->os_version + match[1].rm_so);
            }
            // Get os_patch
            if (w_regexec("^[0-9]+\\.[0-9]+\\.([0-9]+)*", info->os_version, 2, match)) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, info->os_patch);
                snprintf(info->os_patch, match_size + 1, "%.*s", match_size, info->os_version + match[1].rm_so);
            }
            // Get OSX codename
            if (info->os_platform && strcmp(info->os_platform,"darwin") == 0) {
                if (info->os_codename) {
                    char * tmp_os_version;
                    size_t len = 4;
                    len += strlen(info->os_version);
                    len += strlen(info->os_codename);
                    os_malloc(len, tmp_os_version);
                    snprintf(tmp_os_version, len, "%s (%s)", info->os_version, info->os_codename);
                    free(info->os_version);
                    info->os_version = tmp_os_version;
                }
            }
        }
    } else {
        // Empty version
        os_strdup("0.0", info->os_version);
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
        free(osinfo->os_patch);
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

    if (!(fp = wfopen("/proc/cpuinfo", "r"))) {
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

int compare_wazuh_versions(const char *version1, const char *version2, bool compare_patch) {
    char ver1[10];
    char ver2[10];
    char *tmp_v1 = NULL;
    char *tmp_v2 = NULL;
    char *token = NULL;
    int patch1 = 0;
    int major1 = 0;
    int minor1 = 0;
    int patch2 = 0;
    int major2 = 0;
    int minor2 = 0;
    int result = 0;

    if (version1) {
        strncpy(ver1, version1, 9);

        if (tmp_v1 = strchr(ver1, 'v'), tmp_v1) {
            tmp_v1++;
        } else {
            tmp_v1 = ver1;
        }

        if (token = strtok(tmp_v1, "."), token) {
            major1 = atoi(token);

            if (token = strtok(NULL, "."), token) {
                minor1 = atoi(token);

                if (token = strtok(NULL, "."), token) {
                    patch1 = atoi(token);
                }
            }
        }
    }

    if (version2) {
        strncpy(ver2, version2, 9);

        if (tmp_v2 = strchr(ver2, 'v'), tmp_v2) {
            tmp_v2++;
        } else {
            tmp_v2 = ver2;
        }

        if (token = strtok(tmp_v2, "."), token) {
            major2 = atoi(token);

            if (token = strtok(NULL, "."), token) {
                minor2 = atoi(token);

                if (token = strtok(NULL, "."), token) {
                    patch2 = atoi(token);
                }
            }
        }
    }

    if (major1 > major2) {
        result = 1;
    } else if (major1 < major2){
        result = -1;
    } else {
        if(minor1 > minor2) {
            result = 1;
        } else if (minor1 < minor2) {
            result = -1;
        } else if (compare_patch) {
            if (patch1 > patch2) {
                result = 1;
            } else if (patch1 < patch2) {
                result = -1;
            } else {
                result = 0;
            }
        } else {
            result = 0;
        }
    }

    return result;
}
