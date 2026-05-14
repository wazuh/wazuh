/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef VALIDATE_H
#define VALIDATE_H


/* Run-time definitions */
int getDefine_Int(const char *high_name, const char *low_name, int min, int max) __attribute__((nonnull));


/**
 * @brief Check if IP_address is present at that_ip
 *
 * @param ip_address IP address.
 * @param that_ip Struct os_ip to check.
 * @return Returns 1 on success or 0 on failure.
 */
int OS_IPFound(const char *ip_address, const os_ip *that_ip) __attribute__((nonnull));


/**
 * @brief Check if IP_address is present at that_ip
 *
 * @param ip_address IP address.
 * @param list_of_ips List of os_ip struct to check.
 * @return Returns 1 on success or 0 on failure.
 */
int OS_IPFoundList(const char *ip_address, os_ip **list_of_ips);// __attribute__((nonnull));


/**
 * @brief Validate if an IP address is in the right format
 *
 * @param ip_address [in] IP address.
 * @param final_ip [out] Struct os_ip with the given IP address.
 * @return Returns 0 if doesn't match or 1 if it does (or 2 if it has a CIDR).
 */
int OS_IsValidIP(const char *ip_address, os_ip *final_ip);


/**
 * @brief Check if an IPv4 address is embedded in an IPv6 address and resolve it.
 *
 * @param ip_address IPv6 address to be analized, if it contains an IPv4, it will be modified with it.
 * @param size Size of the address buffer.
 * @return Returns 0 if doesn't match or 1 if it does.
 */
int OS_GetIPv4FromIPv6(char *ip_address, size_t size);


/**
 * @brief Expand IPv6 to its full representation.
 *
 * @param ip_address IPv6 address to be expanded, it will be modified with its full representation.
 * @param size Size of the address buffer.
 * @return Returns 0 on success or -1 on failure.
 */
int OS_ExpandIPv6(char *ip_address, size_t size);


/**
 * @brief Validate if a time is in an acceptable format.
 *
 * Acceptable formats:
 *      hh:mm - hh:mm (24 hour format)
 *      !hh:mm - hh:mm (24 hour format)
 *      hh - hh (24 hour format)
 *      hh:mm am - hh:mm pm (12 hour format)
 *      hh am - hh pm (12 hour format)
 *
 * @param time_str Time to be validated.
 * @return Returns 0 if doesn't match or a valid string in success.
 */
char *OS_IsValidTime(const char *time_str);


/**
 * @brief Validate if a time is in an acceptable format, but only accepts a unique time, not a range.
 *
 * @param time_str Time to be validated.
 * @return Returns 0 if doesn't match or a valid string in success.
 */
char *OS_IsValidUniqueTime(const char *time_str) __attribute__((nonnull));


/**
 * @brief Validate if a time is in on a specied time interval.
 *        Must be a valid string, called after OS_IsValidTime().
 * @param time_str Time to be validated.
 * @param ossec_time Time interval.
 * @return Returns 1 on success or 0 on failure.
 */
int OS_IsonTime(const char *time_str, const char *ossec_time) __attribute__((nonnull));


/**
 * @brief Checks if time is the same or has passed a specified one.
 *        Must be a valid string, called after OS_IsValidTime().
 * @param time_str Time to be validated.
 * @param ossec_time Time interval.
 * @return Returns 1 on success or 0 on failure.
 */
int OS_IsAfterTime(const char *time_str, const char *ossec_time) __attribute__((nonnull));


/**
 * @brief Checks if time is the same or has passed a specified one.
 *    Acceptable formats:
 *      weekdays, weekends, monday, tuesday, thursday,..
 *      monday,tuesday
 *      mon,tue wed
 * @param day_str Day to be validated.
 * @return Returns 0 if doesn't match or a valid string in success.
 */
char *OS_IsValidDay(const char *day_str);


/**
 * @brief Check if the specified week day is in the range.
 *
 * @param week_day Day of the week.
 * @param ossec_day Interval.
 * @return Returns 1 on success or 0 on failure.
 */
int OS_IsonDay(int week_day, const char *ossec_day) __attribute__((nonnull));


/**
 * @brief Convert a CIDR into string: aaa.bbb.ccc.ddd[/ee]
 *
 * @param ip [in] IP to be converted.
 * @param string [out] Allocated string to store the IP.
 * @param size [in] Size of the allocated string.
 * @return Returns 0 on success or -1 on failure.
 */
int OS_CIDRtoStr(const os_ip * ip, char * string, size_t size);


/**
 * @brief Validate the day of the week set and retrieve its corresponding integer value.
 *
 * @param day_str Day of the week.
 * @return Return day of the week. If not found, -1 is returned.
 */
int w_validate_wday(const char * day_str);


/**
 * @brief Validate a given time.
 *        Acceptable format: hh:mm (24 hour format)
 *
 * @param time_str Time to be validated.
 * @return Returns NULL on error or a valid string in success.
 */
char * w_validate_time(const char * time_str);


/**
 * @brief Validate if the specified interval is multiple of weeks or days.
 *
 * @param interval Interval to be validated.
 * @param force Set to 0 to check if it is multiple of days or 1 for weeks.
 * @return Returns 0 if the interval is multiple, -1 otherwise.
 */
int w_validate_interval(int interval, int force);


/**
 * @brief Convert to bytes
 *
 * @param content string to validate
 * @return number of bytes on success, otherwise -1
 */
long long w_validate_bytes(const char *content);


/* Macros */

/* Check if the IP is a single host, not a network with a netmask */
#define isSingleHost(x) ((x->is_ipv6) ? false : (x->ipv4->netmask == 0xFFFFFFFF))


#endif /* VALIDATE_H */
