/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "validate_op.h"
#include "expression.h"
#include "../os_net/os_net.h"

#ifdef WAZUH_UNIT_TESTING
#define static

#undef OSSEC_DEFINES
#define OSSEC_DEFINES   "./internal_options.conf"

#undef OSSEC_LDEFINES
#define OSSEC_LDEFINES   "./local_internal_options.conf"
#endif

#define DEFAULT_IPV6_PREFIX  128
#define DEFAULT_IPV4_NETMASK 32


static char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));
static void _init_masks(void);
static const char *__gethour(const char *str, char *ossec_hour, const size_t ossec_hour_len) __attribute__((nonnull));

/**
 * @brief Convert the netmask from an integer value, valid from 0 to 128.
 *
 * @param[in] netnumb Integer value of the netmask.
 * @param[out] nmask6 structure to complete value of the netmask.
 * @return Returns 0 on success or -1 on failure.
 */
static int convertNetmask(int netnumb, struct in6_addr *nmask6);

/**
 * @brief Get CIDR from IPv6 netmask.
 *
 * @param[in] netmask IPV6 netmask.
 * @return CIDR representation of IPv6 netmask.
 */
static int getCIDRipv6(uint8_t *netmask);

/* Global variables */
static int _mask_inited = 0;
static unsigned int _netmasks[33];


/*
* ipv4 alone; or ipv4 + CIDR; or ipv4 + netmask
*             example:  "10.10.10.10" or "10.10.10.10/32" or "10.10.10.10/255.255.255.255"
*
* ipv6 format: uncompress and compress IPv6 supported, with or without prefix
*             example: "2001:db8:abcd:0012:0000:0000:0000:0000" or "11AA::11AA" or "::11AA:11AA:11AA:11AA/64"
*/

#define IPV4_ADDRESS "(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\x5c.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
#define IPV6_PREFIX "12[0-8]|1[0-1][0-9]|[0-9]?[0-9]"

#define IPV4_MASK_IPV6 "^::[fF]{4}:("IPV4_ADDRESS"(?:\x2F(?:(?:3[0-2]|[1-2]?[0-9])|"IPV4_ADDRESS"))?)$"

static  char *ip_address_regex[] = {
// IPv4
"^(?:::[fF]{4}:)?("IPV4_ADDRESS")(?:\x2F((?:3[0-2]|[1-2]?[0-9])|"IPV4_ADDRESS"))?$",
// IPv6
"^((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1,6}(?::[0-9a-fA-F]{1,4}){1})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1}(?::[0-9a-fA-F]{1,4}){1,6})(?:\x2F("IPV6_PREFIX"))?$",
"^((?:[0-9a-fA-F]{1,4}:){1,7}:)(?:\x2F("IPV6_PREFIX"))?$",
"^(:(?::[0-9a-fA-F]{1,4}){1,7})(?:\x2F("IPV6_PREFIX"))?$",
"^(::)$",
NULL,
};

/* Read the file and return a string the matches the following
 * format: high_name.low_name.
 * If return is not null, value must be freed
 */
static char *_read_file(const char *high_name, const char *low_name, const char *defines_file)
{
    FILE *fp;
    char buf[OS_SIZE_1024 + 1];
    char *buf_pt;
    char *tmp_buffer;
    char *ret;
    int i;

    fp = wfopen(defines_file, "r");
    if (!fp) {
        if (strcmp(defines_file, OSSEC_LDEFINES) != 0) {
            merror(FOPEN_ERROR, defines_file, errno, strerror(errno));
        }
        return (NULL);
    }
    w_file_cloexec(fp);

    /* Invalid call */
    if (!high_name || !low_name) {
        merror(NULL_ERROR);
        fclose(fp);
        return (NULL);
    }

    /* Read it */
    buf[OS_SIZE_1024] = '\0';
    while (fgets(buf, OS_SIZE_1024 , fp) != NULL) {
        /* Commented or blank lines */
        if (buf[0] == '#' || buf[0] == ' ' || buf[0] == '\n') {
            continue;
        }

        /* Messages not formatted correctly */
        buf_pt = strchr(buf, '.');
        if (!buf_pt) {
            merror(FGETS_ERROR, defines_file, buf);
            continue;
        }

        /* Check for the high name */
        *buf_pt = '\0';
        buf_pt++;
        if (strcmp(buf, high_name) != 0) {
            continue;
        }

        tmp_buffer = buf_pt;

        /* Get the equal */
        buf_pt = strchr(buf_pt, '=');
        if (!buf_pt) {
            merror(FGETS_ERROR, defines_file, buf);
            continue;
        }

        /* Prepare buf_pt to access the value for this option */
        *buf_pt = '\0';
        buf_pt++;

        /* Remove possible whitespaces between the low name and the equal sign */
        i = (strlen(tmp_buffer) - 1);
        while(tmp_buffer[i] == ' ')
        {
            tmp_buffer[i] = '\0';
            i--;
        }

        /* Check for the low name */
        if (strcmp(tmp_buffer, low_name) != 0) {
            continue;
        }

        /* Ignore possible whitespaces between the equal sign and the value for this option */
        while(*buf_pt == ' ') buf_pt++;

        /* Remove newlines or anything that will cause errors */
        tmp_buffer = strrchr(buf_pt, '\n');
        if (tmp_buffer) {
            *tmp_buffer = '\0';
        }
        tmp_buffer = strrchr(buf_pt, '\r');
        if (tmp_buffer) {
            *tmp_buffer = '\0';
        }

        os_strdup(buf_pt, ret);
        fclose(fp);
        return (ret);
    }

    fclose(fp);
    return (NULL);
}

/* Convert to netmasks from CIDR number */
static int convertNetmask(int netnumb, struct in6_addr *nmask6)
{
    if (netnumb < 0 || netnumb > 128) {
        return -1;
    }

    uint32_t aux = 0;
    uint32_t index = 0;
    uint8_t variable_size = 8;

    for (int i = 0; i < 16; i++) {
#ifndef WIN32
        nmask6->s6_addr[i] = 0;
#else
        nmask6->u.Byte[i] = 0;
#endif
        index = ((netnumb > variable_size) ? variable_size : netnumb);
        netnumb -= index;

        for (uint8_t a = 0; a < index; a++) {
            aux = variable_size - a -1;
#ifndef WIN32
            nmask6->s6_addr[i] += UINT8_C(1) << aux;
#else
            nmask6->u.Byte[i] += UINT8_C(1) << aux;
#endif
        }
    }
    return 0;
}

/* Initialize netmasks -- taken from snort util.c */
static void _init_masks()
{
    _mask_inited = 1;
    _netmasks[0] = 0x0;
    _netmasks[1] = 0x80000000;
    _netmasks[2] = 0xC0000000;
    _netmasks[3] = 0xE0000000;
    _netmasks[4] = 0xF0000000;
    _netmasks[5] = 0xF8000000;
    _netmasks[6] = 0xFC000000;
    _netmasks[7] = 0xFE000000;
    _netmasks[8] = 0xFF000000;
    _netmasks[9] = 0xFF800000;
    _netmasks[10] = 0xFFC00000;
    _netmasks[11] = 0xFFE00000;
    _netmasks[12] = 0xFFF00000;
    _netmasks[13] = 0xFFF80000;
    _netmasks[14] = 0xFFFC0000;
    _netmasks[15] = 0xFFFE0000;
    _netmasks[16] = 0xFFFF0000;
    _netmasks[17] = 0xFFFF8000;
    _netmasks[18] = 0xFFFFC000;
    _netmasks[19] = 0xFFFFE000;
    _netmasks[20] = 0xFFFFF000;
    _netmasks[21] = 0xFFFFF800;
    _netmasks[22] = 0xFFFFFC00;
    _netmasks[23] = 0xFFFFFE00;
    _netmasks[24] = 0xFFFFFF00;
    _netmasks[25] = 0xFFFFFF80;
    _netmasks[26] = 0xFFFFFFC0;
    _netmasks[27] = 0xFFFFFFE0;
    _netmasks[28] = 0xFFFFFFF0;
    _netmasks[29] = 0xFFFFFFF8;
    _netmasks[30] = 0xFFFFFFFC;
    _netmasks[31] = 0xFFFFFFFE;
    _netmasks[32] = 0xFFFFFFFF;
}

/* Get an integer definition. This function always return on
 * success or exits on error.
 */
int getDefine_Int(const char *high_name, const char *low_name, int min, int max)
{
    int ret;
    char *value;
    char *pt;

    /* Try to read from the local define file */
    value = _read_file(high_name, low_name, OSSEC_LDEFINES);
    if (!value) {
        value = _read_file(high_name, low_name, OSSEC_DEFINES);
        if (!value) {
            merror_exit(DEF_NOT_FOUND, high_name, low_name);
        }
    }

    pt = value;
    while (*pt != '\0') {
        if (!isdigit((int)*pt)) {
            merror_exit(INV_DEF, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if ((ret < min) || (ret > max)) {
        merror_exit(INV_DEF, high_name, low_name, value);
    }

    /* Clear memory */
    free(value);

    return (ret);
}

/* Check if IP_address is present at that_IP
 * Returns 1 on success or 0 on failure
 */
int OS_IPFound(const char *ip_address, const os_ip *that_ip)
{
    int _true = 1;
    bool is_ipv6 = false;
    struct in_addr net;
    struct in6_addr net6;

    /* Extract IP address */
    if (OS_SUCCESS == get_ipv4_numeric(ip_address, &net)) {
        is_ipv6 = false;
    } else if (OS_SUCCESS == get_ipv6_numeric(ip_address, &net6)) {
        is_ipv6 = true;
    } else {
        return (!_true);
    }

    /* If negate is set */
    if (that_ip->ip[0] == '!') {
        _true = 0;
    }

    /* Check if IP is in thatip & netmask */
    if (is_ipv6) {
        for(unsigned int i = 0; i < 16; i++) {
#ifndef WIN32
            if ((net6.s6_addr[i] & that_ip->ipv6->netmask[i]) != that_ip->ipv6->ip_address[i]) {
#else
            if ((net6.u.Byte[i] & that_ip->ipv6->netmask[i]) != that_ip->ipv6->ip_address[i]) {
#endif
                break;
            } else if (i >= (15)) {
                return (_true);
            }
        }
    } else {
        if ((net.s_addr & that_ip->ipv4->netmask) == that_ip->ipv4->ip_address) {
            return (_true);
        }
    }

    /* Didn't match */
    return (!_true);
}

/* Check if IP_address is present in the "list_of_ips".
 * Returns 1 on success or 0 on failure
 * The list MUST be NULL terminated
 */
int OS_IPFoundList(const char *ip_address, os_ip **list_of_ips)
{
    int _true = 1;
    bool is_ipv6 = false;
    struct in_addr net;
    struct in6_addr net6;

    /* Extract IP address */
    if (OS_SUCCESS == get_ipv4_numeric(ip_address, &net)) {
        is_ipv6 = false;
    } else if (OS_SUCCESS == get_ipv6_numeric(ip_address, &net6)) {
        is_ipv6 = true;
    } else {
        return (!_true);
    }

    while (*list_of_ips) {
        os_ip *l_ip = *list_of_ips;

        if (l_ip->ip[0] == '!') {
            _true = 0;
        }

        /* Check if IP is in thatip & netmask */
        if (is_ipv6) {
            for(unsigned int i = 0; i < 16; i++) {
#ifndef WIN32
                if ((net6.s6_addr[i] & l_ip->ipv6->netmask[i]) != l_ip->ipv6->ip_address[i]) {
#else
                if ((net6.u.Byte[i] & l_ip->ipv6->netmask[i]) != l_ip->ipv6->ip_address[i]) {
#endif
                    break;
                } else if (i >= (15)) {
                    return (_true);
                }
            }
        } else {
            if ((net.s_addr & l_ip->ipv4->netmask) == l_ip->ipv4->ip_address) {
                return (_true);
            }
        }

        list_of_ips++;
    }

    return (!_true);
}

/* Validate if an IP address is in the right format
 * Returns 0 if doesn't match or 1 if it is an IP or 2 an IP with CIDR.
 * WARNING: On success this function may modify the value of ip_address
 */
int OS_IsValidIP(const char *ip_address, os_ip *final_ip)
{
    unsigned int ret = 0;

    /* Can't be null */
    if (!ip_address) {
        return (0);
    }

    if (*ip_address == '!') {
        ip_address++;
    }

    /* Assign the IP address */
    if (final_ip) {
        memset(final_ip, 0, sizeof(os_ip));
        os_calloc(IPSIZE + 1, sizeof(char), final_ip->ip);
        strncpy(final_ip->ip, ip_address, IPSIZE);
        OS_GetIPv4FromIPv6(final_ip->ip, IPSIZE);
    }

    if (strcmp(ip_address, "any") != 0) {

        w_expression_t * exp;
        unsigned int i = 0;

        regex_matching * regex_match = NULL;
        os_calloc(1, sizeof(regex_matching), regex_match);

        while (ip_address_regex[i] != NULL) {

            w_calloc_expression_t(&exp, EXP_TYPE_PCRE2);
            if (w_expression_compile(exp, ip_address_regex[i], 0) &&
                 w_expression_match(exp, ip_address, NULL, regex_match)) {

                /* number of regex captures */
                int sub_strings_num = 0;
                if (regex_match->sub_strings) {
                    for (sub_strings_num = 0; regex_match->sub_strings[sub_strings_num] != NULL; sub_strings_num++);
                }

                ret = sub_strings_num == 2 ? 2 : 1;

                if (final_ip) {
                    /* Regex 0 (i = 0) match IPv4, superior regex match IPv6 */
                    if (i > 0) {
                        /* IPv6 */
                        os_calloc(1, sizeof(os_ipv6), final_ip->ipv6);
                        final_ip->is_ipv6 = TRUE;

                        /* At this point regex can capture 1 or 2 strings, first is the ip and second the prefix */
                        if (sub_strings_num > 0) {
                            /* IP Address captured */
                            struct in6_addr net6;
                            struct in6_addr nmask6;
                            memset(&net6, 0, sizeof(net6));
                            memset(&nmask6, 0, sizeof(nmask6));

                            if (OS_INVALID == get_ipv6_numeric(regex_match->sub_strings[0], &net6)) {
                                ret = 0;
                                break;
                            }

                            if (sub_strings_num == 2) {
                                /* prefix */
                                int cidr = atoi(regex_match->sub_strings[1]);
                                if ((strlen(regex_match->sub_strings[1]) > 3) ||
                                      convertNetmask(cidr, &nmask6)) {
                                    ret = 0;
                                    break;
                                }
                            } else if (convertNetmask(DEFAULT_IPV6_PREFIX, &nmask6)) {
                                ret = 0;
                                break;
                            }
#ifndef WIN32
                            for(unsigned int i = 0; i < 16; i++) {
                                final_ip->ipv6->ip_address[i] = net6.s6_addr[i] & nmask6.s6_addr[i];
                            }
                            memcpy(final_ip->ipv6->netmask, nmask6.s6_addr, sizeof(final_ip->ipv6->netmask));
#else
                            for(unsigned int i = 0; i < 16; i++) {
                                final_ip->ipv6->ip_address[i] = net6.u.Byte[i] & nmask6.u.Byte[i];
                            }
                            memcpy(final_ip->ipv6->netmask, nmask6.u.Byte, sizeof(final_ip->ipv6->netmask));
#endif
                            OS_ExpandIPv6(final_ip->ip, IPSIZE);

                        } else {
                            ret = 0;
                            break;
                        }
                    } else {
                        /* IPv4 */
                        os_calloc(1, sizeof(os_ipv4), final_ip->ipv4);
                        final_ip->is_ipv6 = FALSE;

                        /* At this point regex can capture 1 or 2 strings, ip and CIDR or netmask */
                        if (sub_strings_num > 0) {
                            /* IP Address captured */
                            struct in_addr net;
                            struct in_addr nmask;
                            memset(&net, 0, sizeof(net));
                            memset(&nmask, 0, sizeof(nmask));

                            if (OS_INVALID == get_ipv4_numeric(regex_match->sub_strings[0], &net)) {
                                if (strcmp("0.0.0.0", regex_match->sub_strings[0]) == 0) {
                                    net.s_addr = 0;
                                } else {
                                    ret = 0;
                                    break;
                                }
                            }

                            if (sub_strings_num == 2) {
                                /* CIDR or Netmask */
                                if (strlen(regex_match->sub_strings[1]) <= 2) {
                                    int cidr = atoi(regex_match->sub_strings[1]);
                                    if (!_mask_inited) {
                                        _init_masks();
                                    }
                                    nmask.s_addr = htonl(_netmasks[cidr]);
                                } else if (OS_INVALID == get_ipv4_numeric(regex_match->sub_strings[1], &nmask)) {
                                    ret = 0;
                                    break;
                                }
                            } else {
                                if (!_mask_inited) {
                                    _init_masks();
                                }
                                nmask.s_addr = htonl(_netmasks[DEFAULT_IPV4_NETMASK]);
                            }

                            final_ip->ipv4->ip_address = net.s_addr & nmask.s_addr;
                            final_ip->ipv4->netmask = nmask.s_addr;

                        } else {
                            ret = 0;
                            break;
                        }
                    }
                }
                break;
            }
            w_free_expression_t(&exp);
            i++;
        }

        OSRegex_free_regex_matching(regex_match);
        os_free(regex_match)
        w_free_expression_t(&exp);
    }
    else {
        /* any case */
        if (final_ip) {
            os_calloc(1, sizeof(os_ipv6), final_ip->ipv6);
            memset(final_ip->ipv6->ip_address, 0, sizeof(final_ip->ipv6->ip_address));
            memset(final_ip->ipv6->netmask, 0, sizeof(final_ip->ipv6->netmask));
        }
        ret = 2;
    }

    return ret;
}

/* Extract embedded IPv4 from IPv6 */
int OS_GetIPv4FromIPv6(char *ip_address, size_t size)
{
    w_expression_t * exp;
    int ret = 0;

    regex_matching * regex_match = NULL;
    os_calloc(1, sizeof(regex_matching), regex_match);

    w_calloc_expression_t(&exp, EXP_TYPE_PCRE2);
    if (w_expression_compile(exp, IPV4_MASK_IPV6, 0) &&
         w_expression_match(exp, ip_address, NULL, regex_match)) {

        /* number of regex captures */
        if (regex_match->sub_strings && regex_match->sub_strings[0]) {
            strncpy(ip_address, regex_match->sub_strings[0], size);
            ret = 1;
        }
    }

    OSRegex_free_regex_matching(regex_match);
    os_free(regex_match)
    w_free_expression_t(&exp);
    return ret;
}

/* Expand IPv6 address */
int OS_ExpandIPv6(char *ip_address, size_t size)
{
    struct in6_addr net6;
    char aux_ip[IPSIZE + 1] = {0};
    char *save_ptr = NULL;

    memset(&net6, 0, sizeof(net6));
    strncpy(aux_ip, ip_address, IPSIZE);

    if (OS_INVALID == get_ipv6_numeric(strtok_r(aux_ip, "/", &save_ptr), &net6)) {
        return OS_INVALID;
    }

    uint8_t aux[16];
    for(unsigned int i = 0; i < 16; i++) {
#ifndef WIN32
        aux[i] = net6.s6_addr[i];
#else
        aux[i] = net6.u.Byte[i];
#endif
    }

    /* In case of ip_address has CIDR */
    int cidr = 0;
    char *cidr_str = strtok_r(NULL, "/", &save_ptr);
    if (cidr_str) {
        cidr = atoi(cidr_str);
        if (cidr < 0 || cidr > DEFAULT_IPV6_PREFIX) {
            return OS_INVALID;
        }
    }

    if (cidr) {
        snprintf(ip_address, size, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X/%u",
            (int)aux[0], (int)aux[1], (int)aux[2], (int)aux[3],
            (int)aux[4], (int)aux[5], (int)aux[6], (int)aux[7],
            (int)aux[8], (int)aux[9], (int)aux[10], (int)aux[11],
            (int)aux[12], (int)aux[13], (int)aux[14], (int)aux[15], cidr);
    } else {
        snprintf(ip_address, size, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
            (int)aux[0], (int)aux[1], (int)aux[2], (int)aux[3],
            (int)aux[4], (int)aux[5], (int)aux[6], (int)aux[7],
            (int)aux[8], (int)aux[9], (int)aux[10], (int)aux[11],
            (int)aux[12], (int)aux[13], (int)aux[14], (int)aux[15]);
    }

    return OS_SUCCESS;
}

/* Must be a valid string, called after OS_IsValidTime
 * Returns 1 on success or 0 on failure
 */
int OS_IsonTime(const char *time_str, const char *ossec_time)
{
    int _true = 1;

    if (*ossec_time == '!') {
        _true = 0;
    }
    ossec_time++;

    /* Comparing against min/max value */
    if ((strncmp(time_str, ossec_time, 5) >= 0) &&
            (strncmp(time_str, ossec_time + 5, 5) <= 0)) {
        return (_true);
    }

    return (!_true);
}

/* Validate if a time is in an acceptable format for OSSEC.
 * Returns 0 if doesn't match or a valid string for OSSEC usage in success.
 * ** On success this function may modify the value of date
 * Acceptable formats:
 *      hh:mm - hh:mm (24 hour format)
 *      !hh:mm -hh:mm (24 hour format)
 *      hh - hh (24 hour format)
 *      hh:mm am - hh:mm pm (12 hour format)
 *      hh am - hh pm (12 hour format)
 */
#define RM_WHITE(x)while(*x == ' ')x++;

static const char *__gethour(const char *str, char *ossec_hour, const size_t ossec_hour_len)
{
    int _size = 0;
    int chour = 0;
    int cmin = 0;

    /* Invalid time format */
    if (!isdigit((int)*str)) {
        merror(INVALID_TIME, str);
    }

    /* Hour */
    chour = atoi(str);

    /* Get a valid hour */
    if (chour < 0 || chour >= 24) {
        merror(INVALID_TIME, str);
        return (NULL);
    }

    /* Go after the hour */
    while (isdigit((int)*str)) {
        _size++;
        str++;
    }

    /* Invalid hour */
    if (_size > 2) {
        merror(INVALID_TIME, str);
        return (NULL);
    }

    /* Get minute */
    if (*str == ':') {
        str++;
        if ((!isdigit((int)*str) ||
                !isdigit((int) * (str + 1))) && isdigit((int) * (str + 2))) {
            merror(INVALID_TIME, str);
            return (NULL);
        }

        cmin = atoi(str);
        str += 2;
    }

    /* Remove spaces */
    RM_WHITE(str);

    if ((*str == 'a') || (*str == 'A')) {
        str++;
        if ((*str == 'm') || (*str == 'M')) {
            if (chour == 12) chour = 0;
            const int bytes_written = snprintf(ossec_hour, ossec_hour_len, "%02d:%02d", chour, cmin);

            if (bytes_written < 0 || (size_t)bytes_written >= ossec_hour_len) {
                return (NULL);
            }

            str++;
            return (str);
        }
    } else if ((*str == 'p') || (*str == 'P')) {
        str++;
        if ((*str == 'm') || (*str == 'M')) {
            if (chour == 12) chour = 0;
            chour += 12;

            /* New hour must be valid */
            if (chour < 0 || chour >= 24) {
                merror(INVALID_TIME, str);
                return (NULL);
            }

            const int bytes_written = snprintf(ossec_hour, ossec_hour_len, "%02d:%02d", chour, cmin);

            if (bytes_written < 0 || (size_t)bytes_written >= ossec_hour_len) {
                return (NULL);
            }

            str++;
            return (str);
        }

    } else {
        const int bytes_written = snprintf(ossec_hour, ossec_hour_len, "%02d:%02d", chour, cmin);

        if (bytes_written < 0 || (size_t)bytes_written >= ossec_hour_len) {
            return (NULL);
        }

        return (str);
    }

    /* Here is error */
    merror(INVALID_TIME, str);
    return (NULL);
}

char *OS_IsValidTime(const char *time_str)
{
    char *ret;
    char first_hour[7];
    char second_hour[7];
    int ng = 0;

    /* Must be not null */
    if (!time_str) {
        return (NULL);
    }

    /* Clear memory */
    memset(first_hour, '\0', 7);
    memset(second_hour, '\0', 7);

    /* Remove spaces */
    RM_WHITE(time_str);

    /* Check for negative */
    if (*time_str == '!') {
        ng = 1;
        time_str++;

        /* We may have spaces after the '!' */
        RM_WHITE(time_str);
    }

    /* Get first hour */
    time_str = __gethour(time_str, first_hour, sizeof(first_hour));

    if (!time_str) {
        return (NULL);
    }

    /* Remove spaces */
    RM_WHITE(time_str);

    if (*time_str != '-') {
        return (NULL);
    }

    time_str++;

    /* Remove spaces */
    RM_WHITE(time_str);

    /* Get second hour */
    time_str = __gethour(time_str, second_hour, sizeof(second_hour));
    if (!time_str) {
        return (NULL);
    }

    RM_WHITE(time_str);
    if (*time_str != '\0') {
        return (NULL);
    }

    os_calloc(16, sizeof(char), ret);

    /* Fix dump hours */
    if (strcmp(first_hour, second_hour) > 0) {
        snprintf(ret, 16, "!%s%s", second_hour, first_hour);
        return (ret);
    }

    /* For the normal times */
    snprintf(ret, 16, "%c%s%s", ng == 0 ? '.' : '!', first_hour, second_hour);

    return (ret);
}

/* Check if the current time is the same or has passed the specified one */
int OS_IsAfterTime(const char *time_str, const char *ossec_time)
{
    /* Unique times can't have a ! */
    if (*ossec_time == '!') {
        return (0);
    }

    ossec_time++;

    /* Compare against min/max value */
    if (strncmp(time_str, ossec_time, 5) >= 0) {
        return (1);
    }

    return (0);
}

/* Create a unique time, not a range. Must be used with OS_IsAfterTime. */
char *OS_IsValidUniqueTime(const char *time_str)
{
    char mytime[128 + 1];

    if (*time_str == '!') {
        return (NULL);
    }

    memset(mytime, '\0', 128 + 1);
    snprintf(mytime, 128, "%s-%s", time_str, time_str);

    return (OS_IsValidTime(mytime));
}

/* Check if the specified week day is in the range */
int OS_IsonDay(int week_day, const char *ossec_day)
{
    int _true = 1;

    /* Negative */
    if (ossec_day[7] == '!') {
        _true = 0;
    }

    if (week_day < 0 || week_day > 7) {
        return (0);
    }

    /* It is on the right day */
    if (ossec_day[week_day] == 1) {
        return (_true);
    }

    return (!_true);
}

/* Validate if a day is in an acceptable format for OSSEC
 * Returns 0 if doesn't match or a valid string for OSSEC usage in success.
 * WARNING: On success this function may modify the value of date
 * Acceptable formats:
 *  weekdays, weekends, monday, tuesday, thursday,..
 *  monday,tuesday
 *  mon,tue wed
 */
#define RM_SEP(x)while((*x == ' ') || (*x == ','))x++;

#define IS_SEP(x) (*x == ' ' || *x == ',')

char *OS_IsValidDay(const char *day_str)
{
    int i = 0, ng = 0;
    char *ret;
    char day_ret[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char *(days[]) = {
        "sunday", "sun", "monday", "mon", "tuesday", "tue",
        "wednesday", "wed", "thursday", "thu", "friday",
        "fri", "saturday", "sat", "weekdays", "weekends", NULL
    };
    int days_int[] = {0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 8};

    /* Must be a valid string */
    if (!day_str) {
        return (NULL);
    }

    RM_WHITE(day_str);

    /* Check for negatives */
    if (*day_str == '!') {
        ng = 1;
        RM_WHITE(day_str);
    }

    while (*day_str != '\0') {
        i = 0;
        while (days[i]) {
            if (strncasecmp(day_str, days[i], strlen(days[i])) == 0) {
                /* Weekdays */
                if (days_int[i] == 7) {
                    day_ret[1] = 1;
                    day_ret[2] = 1;
                    day_ret[3] = 1;
                    day_ret[4] = 1;
                    day_ret[5] = 1;
                }
                /* Weekends */
                else if (days_int[i] == 8) {
                    day_ret[0] = 1;
                    day_ret[6] = 1;
                } else {
                    day_ret[days_int[i]] = 1;
                }
                break;
            }
            i++;
        }

        if (!days[i]) {
            return (NULL);
        }

        day_str += strlen(days[i]);

        if (IS_SEP(day_str)) {
            RM_SEP(day_str);
            continue;
        } else if (*day_str == '\0') {
            break;
        } else {
            return (NULL);
        }
    }

    /* Assign values */
    os_calloc(9, sizeof(char), ret);
    if (ng == 1) {
        /* Set negative */
        ret[7] = '!';
    }

    ng = 0;
    for (i = 0; i <= 6; i++) {
        /* Check if some is checked */
        if (day_ret[i] == 1) {
            ng = 1;
        }
        ret[i] = day_ret[i];
    }

    /* At least one day must be checked */
    if (ng == 0) {
        free(ret);
        return (NULL);
    }

    return (ret);
}

// Convert a CIDR into string: aaa.bbb.ccc.ddd[/ee]
int OS_CIDRtoStr(const os_ip * ip, char * string, size_t size) {
    int imask = 0;
    bool is_ipv6 = false;
    uint32_t hmask;

    if (strchr(ip->ip, ':') != NULL) {
        is_ipv6 = true;
        imask = getCIDRipv6(ip->ipv6->netmask);
    }

    if (is_ipv6 && imask < 128) {
        return ((snprintf(string, size, "%s/%u", ip->ip, imask) < (int)size) - 1);

    } else if (!is_ipv6 && (ip->ipv4->netmask != 0xFFFFFFFF) && strcmp(ip->ip, "any")) {
        if (_mask_inited) {
            _init_masks();
        }

        hmask = ntohl(ip->ipv4->netmask);
        for (imask = 0; imask < 32 && _netmasks[imask] != hmask; imask++);
        return (imask < 32) ? ((snprintf(string, size, "%s/%u", ip->ip, imask) < (int)size) - 1) : -1;

    } else {
        strncpy(string, ip->ip, size - 1);
        string[size - 1] = '\0';
        return 0;
    }
}

// Get CIDR from IPv6 netmask
static int getCIDRipv6(uint8_t *netmask) {
    int imask = 0;
    uint8_t aux = 0;
    for (uint8_t i = 0; i < 16; i++) {
        aux = netmask[i];
        for (uint8_t a = 0; a < 8 && aux > 0; a++) {
            if (0x01 & aux) {
                imask++;
            }
            aux = aux >> UINT8_C(1);
        }
    }
    return imask;
}

/* Validate the day of the week set and retrieve its corresponding integer value.
   If not found, -1 is returned.
*/

int w_validate_wday(const char * day_str) {

    int i = 0;

    const char *(days[]) = {
        "sunday", "sun", "monday", "mon", "tuesday", "tue",
        "wednesday", "wed", "thursday", "thu", "friday",
        "fri", "saturday", "sat", NULL
    };

    int days_int[] = {0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6};

    /* Must be a valid string */
    if (!day_str) {
        return -1;
    }

    // Remove spaces
    RM_WHITE(day_str);

    while((days[i] != NULL)) {
        if (strncasecmp(day_str, days[i], strlen(days[i])) == 0) {
            return days_int[i];
        }
        i++;
    }

    merror(INVALID_DAY, day_str);
    return -1;

}

// Acceptable format: hh:mm (24 hour format)
char * w_validate_time(const char * time_str) {

    int hour = -1;
    int min = -1;
    char * ret_time = NULL;

    if (!time_str) {
        return NULL;
    }

    /* Remove spaces */
    RM_WHITE(time_str);

    if (!strchr(time_str, ':')) {
        merror(INVALID_TIME, time_str);
        return NULL;
    }

    if (sscanf(time_str, "%d:%d", &hour, &min) < 0) {
        merror(INVALID_TIME, time_str);
        return NULL;
    } else {
        if ((hour < 0 || hour >= 24) || (min < 0 || min >= 60)) {
            merror(INVALID_TIME, time_str);
            return NULL;
        }
    }

    os_calloc(12, sizeof(char), ret_time);
    snprintf(ret_time, 12, "%02d:%02d", hour, min);

    return ret_time;

}

// Validate if the specified interval is multiple of weeks or days
int w_validate_interval(int interval, int force) {

    int ret = -1;

    switch(force) {
        case 0:     // Force to be a multiple of a day
            ret = interval % 86400;
            break;
        case 1:     // Force to be a multiple of a week
            ret = interval % 604800;
            break;
        default:
            merror("At validate_interval(): internal error.");
    }

    return ret;
}

long long w_validate_bytes(const char *content) {

    long long converted_value = 0;
    char * end;
    long read_value = strtol(content, &end, 10);

    if (read_value < 0 || read_value == LONG_MAX || content == end) {
        return -1;
    }

    switch (*end) {
        case 'K':
        case 'k':
            converted_value = read_value * 1024LL;
            break;
        case 'M':
        case 'm':
            converted_value = read_value * (1024 * 1024LL);
            break;
        case 'G':
        case 'g':
            converted_value = read_value * (1024 * 1024 * 1024LL);
            break;
        default:
            converted_value = read_value;
            break;
    }

    return converted_value;
}
