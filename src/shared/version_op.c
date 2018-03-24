/*
 * Copyright (C) 2017 Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "version_op.h"

#ifdef WIN32

os_info *get_win_version()
{
    os_info *info;

    FILE *cmd_output;
    char *command;
    size_t buf_tam = 100;
    size_t ver_length = 60;
    size_t v_length = 20;
    char read_buff[buf_tam];
    int status;

    os_calloc(1,sizeof(os_info),info);

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

    if (osvi.dwMajorVersion == 6) {
        // Read Windows Version
        memset(read_buff, 0, buf_tam);
        command = "wmic os get caption";
        char *end;
        cmd_output = popen(command, "r");
        if (!cmd_output) {
            merror("Unable to execute command: '%s'.", command);
        } else {
            if (fgets(read_buff, buf_tam, cmd_output) && strncmp(read_buff, "Caption", 7) == 0) {
                if (!fgets(read_buff, buf_tam, cmd_output)){
                    merror("Can't get OS name.");
                    info->os_name = strdup("unknown");
                }
                else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    info->os_name = strdup(read_buff);
                }else
                    info->os_name = strdup("unknown");
            } else {
                mwarn("Can't get OS name (bad header).");
                info->os_name = strdup("unknown");
            }

            if (status = pclose(cmd_output), status) {
                mwarn("Command 'wmic' returned %d getting OS name.", status);
            }
        }

        // Read version number
        memset(read_buff, 0, buf_tam);
        command = "wmic os get Version";
        cmd_output = popen(command, "r");
        if (!cmd_output) {
            merror("Unable to execute command: '%s'.", command);
            info->os_version = strdup("unknown");
        } else {
            if (fgets(read_buff, buf_tam, cmd_output) && strncmp(read_buff, "Version", 7) == 0) {
                if (!fgets(read_buff, buf_tam, cmd_output)){
                    merror("Can't get version.");
                    info->os_version = strdup("unknown");
                }
                else {
                    info->os_version = strdup(strtok(read_buff," "));
                    char ** parts = NULL;
                    parts = OS_StrBreak('.', info->os_version, 3);
                    info->os_major = strdup(parts[0]);
                    info->os_minor = strdup(parts[1]);
                    info->os_build = strdup(parts[2]);
                    free(parts);
                }
            } else {
                mwarn("Can't get OS version (bad header).");
                info->os_version = strdup("unknown");
            }

            if (status = pclose(cmd_output), status) {
                mwarn("Command 'wmic' returned %d getting OS version.", status);
            }
        }

        // Read version CSName
        memset(read_buff, 0, buf_tam);
        command = "wmic os get CSName";
        cmd_output = popen(command, "r");
        if (!cmd_output) {
            merror("Unable to execute command: '%s'.", command);
            info->nodename = strdup("unknown");
        } else {
            if (fgets(read_buff, buf_tam, cmd_output) && strncmp(read_buff, "CSName", 6) == 0) {
                if (!fgets(read_buff, buf_tam, cmd_output)){
                    merror("Can't get CSName.");
                    info->nodename = strdup("unknown");
                }
                else {
                    info->nodename = strdup(strtok(read_buff," "));
                }
            } else {
                mwarn("Unable to execute command: '%s' (bad header).", command);
                info->nodename = strdup("unknown");
            }

            if (status = pclose(cmd_output), status) {
                mwarn("Command 'wmic' returned %d getting host name.", status);
            }
        }

        // Read OSArchitecture
        memset(read_buff, 0, buf_tam);
        command = "wmic os get OSArchitecture";
        cmd_output = popen(command, "r");
        if (!cmd_output) {
            merror("Unable to execute command: '%s'.", command);
            info->machine = strdup("unknown");
        } else {
            if (fgets(read_buff, buf_tam, cmd_output) && strncmp(read_buff, "OSArchitecture", 14) == 0) {
                if (!fgets(read_buff, buf_tam, cmd_output)){
                    merror("Can't get OSArchitecture.");
                    info->machine = strdup("unknown");
                }
                else {
                    if (strcmp(strtok(read_buff," "), "64-bit") == 0) {
                        info->machine = strdup("x86_64");
                    } else if (strncmp(read_buff, "64", 2) == 0) {
                        info->machine = strdup("x86_64");
                    } else {
                        info->machine = strdup("i686");
                    }
                }
            } else {
                mwarn("Can't get OSArchitecture (bad header).");
                info->machine = strdup("unknown");
            }

            if (status = pclose(cmd_output), status) {
                mwarn("Command 'wmic' returned %d getting OS architecture.", status);
            }
        }
    }
    else {
        if (osvi.dwMajorVersion == 5) {
            if (osvi.dwMinorVersion == 0) {
                info->os_name = strdup("Microsoft Windows 2000");
                info->machine = strdup("i686");
            }
            else if (osvi.dwMinorVersion == 1) {
                info->os_name = strdup("Microsoft Windows XP");
                info->machine = strdup("i686");
            }
            else if (osvi.dwMinorVersion == 2) {
                pGNSI = (PGNSI) GetProcAddress(GetModuleHandle("kernel32.dll"),"GetNativeSystemInfo");
                if (NULL != pGNSI) {
                    pGNSI(&si);
                }
                if (osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                    info->os_name = strdup("Microsoft Windows XP Professional x64 Edition");
                    info->machine = strdup("x86_64");
                }
                else {
                    if ( GetSystemMetrics(89) != 0 ) {
                        info->os_name = strdup("Microsoft Windows Server 2003 R2");
                    }
                    else {
                        info->os_name = strdup("Microsoft Windows Server 2003");
                    }
                    info->machine = strdup("i686");
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
            info->machine = strdup("i686");
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
    /* 17 */ "High Sierra"};
    if (version >= 10 && version <= 17)
        return r_names[version%10];
    else
        return NULL;
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
                          goto free_os_info;
                      }
                  }
                } else {
                  goto free_os_info;
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
    }

    return info;
free_os_info:
    free_osinfo(info);
    return NULL;
}

#endif

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
