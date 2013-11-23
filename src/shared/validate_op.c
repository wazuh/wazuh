/* @(#) $Id: ./src/shared/validate_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC.
 * Available at http://www.ossec.net
 */



#include "shared.h"
char *ip_address_regex =
     "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/?"
     "([0-9]{0,2}|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})$";

/* Read the file and return a string the matches the following
 * format: high_name.low_name.
 * If return is not null, value must be free.
 */
static char *_read_file(char *high_name, char *low_name, char *defines_file)
{
    FILE *fp;
    char def_file[OS_FLSIZE +1];
    char buf[OS_SIZE_1024 +1];
    char *buf_pt;
    char *tmp_buffer;
    char *ret;

    #ifndef WIN32
    if(isChroot())
    {
        snprintf(def_file,OS_FLSIZE,"%s", defines_file);
    }
    else
    {
        snprintf(def_file,OS_FLSIZE,"%s%s",DEFAULTDIR, defines_file);
    }
    #else
    snprintf(def_file,OS_FLSIZE,"%s", defines_file);
    #endif


    fp = fopen(def_file, "r");
    if(!fp)
    {
        if(strcmp(defines_file, OSSEC_LDEFINES) != 0)
        {
            merror(FOPEN_ERROR, __local_name, def_file);
        }
        return(NULL);
    }

    /* Invalid call */
    if(!high_name || !low_name)
    {
        merror(NULL_ERROR, __local_name);
        fclose(fp);
        return(NULL);
    }

    /* Reading it */
    buf[OS_SIZE_1024] = '\0';
    while(fgets(buf, OS_SIZE_1024 , fp) != NULL)
    {
        /* Commented or blank lines */
        if(buf[0] == '#' || buf[0] == ' ' || buf[0] == '\n')
        {
            continue;
        }

        /* Messages not formatted correctly */
        buf_pt = strchr(buf, '.');
        if(!buf_pt)
        {
            merror(FGETS_ERROR, __local_name, def_file, buf);
            continue;
        }

        /* Checking for the high name */
        *buf_pt = '\0'; buf_pt++;
        if(strcmp(buf, high_name) != 0)
        {
            continue;
        }

        tmp_buffer = buf_pt;

        /* Getting the equal */
        buf_pt = strchr(buf_pt, '=');
        if(!buf_pt)
        {
            merror(FGETS_ERROR, __local_name, def_file, buf);
            continue;
        }

        /* Checking for the low name */
        *buf_pt = '\0'; buf_pt++;
        if(strcmp(tmp_buffer, low_name) != 0)
        {
            continue;
        }

        /* Removing new lines or anything that we cause errors */
        tmp_buffer = strrchr(buf_pt, '\n');
        if(tmp_buffer)
        {
            *tmp_buffer = '\0';
        }

        tmp_buffer = strrchr(buf_pt, '\r');
        if(tmp_buffer)
        {
            *tmp_buffer = '\0';
        }

        os_strdup(buf_pt, ret);
        fclose(fp);
        return(ret);
    }

    fclose(fp);
    return(NULL);
}



/** getDefine_Int.
 * Gets an integer definition. This function always return on
 * success or exit on error.
 */
int getDefine_Int(char *high_name, char *low_name, int min, int max)
{
    int ret;
    char *value;
    char *pt;


    /* We first try to read from the local define file. */
    value = _read_file(high_name, low_name, OSSEC_LDEFINES);
    if(!value)
    {
        value = _read_file(high_name, low_name, OSSEC_DEFINES);
        if(!value)
            ErrorExit(DEF_NOT_FOUND, __local_name, high_name, low_name);
    }

    pt = value;
    while(*pt != '\0')
    {
        if(!isdigit((int)*pt))
        {
            ErrorExit(INV_DEF, __local_name, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if((ret < min) || (ret > max))
    {
        ErrorExit(INV_DEF, __local_name, high_name, low_name, value);
    }

    /* Clearing memory */
    free(value);

    return(ret);
}


/** int OS_IPFound(char *ip_address, os_ip *that_ip)
 * Checks if ip_address is present at that_ip.
 * Returns 1 on success or 0 on failure.
 */
int OS_IPFound(char *ip_address, os_ip *that_ip)
{
    int _true = 1;
    os_ip temp_ip;

    memset(&temp_ip, 0, sizeof(struct _os_ip));

    /* Extracting ip address */
    if (OS_IsValidIP(ip_address, &temp_ip) == 0)
    {
        return(!_true);
    }

    /* If negate is set */
    if(that_ip->ip[0] == '!')
    {
        _true = 0;
    }

    /* Checking if ip is in thatip & netmask */
    if (sacmp((struct sockaddr *) &temp_ip.ss, 
              (struct sockaddr *) &that_ip->ss,
              that_ip->prefixlength))
    {
        return(_true);
    }

    /* Didn't match */
    return(!_true);
}


/** int OS_IPFoundList(char *ip_address, os_ip **list_of_ips)
 * Checks if ip_address is present on the "list_of_ips".
 * Returns 1 on success or 0 on failure.
 * The list MUST be NULL terminated
 */
int OS_IPFoundList(char *ip_address, os_ip **list_of_ips)
{
    int _true = 1;
    os_ip temp_ip;

    memset(&temp_ip, 0, sizeof(struct _os_ip));

    /* Extracting ip address */
    if (OS_IsValidIP(ip_address, &temp_ip) == 0)
    {
        return(!_true);
    }

    while(*list_of_ips)
    {
        os_ip *l_ip = *list_of_ips;

        if(l_ip->ip[0] == '!')
        {
            _true = 0;
        }

        /* Checking if ip is in thatip & netmask */
        if (sacmp((struct sockaddr *) &temp_ip.ss, 
                  (struct sockaddr *) &l_ip->ss,
                  l_ip->prefixlength))
        {
            return(_true); 
        }
        list_of_ips++;
    }

    return(!_true);
}


/** int OS_IsValidIP(char *ip_address, os_ip *final_ip)
 * Validates if an ip address is in the right
 * format.
 * Returns 0 if doesn't match or 1 if it is an ip or 2 an ip with cidr.
 * ** On success this function may modify the value of ip_address
 */
int OS_IsValidIP(char *ip_address, os_ip *final_ip)
{
    char *tmp_str;
    int cidr = -1, prefixlength;
    struct addrinfo hints, *result;

    /* Can't be null */
    if(!ip_address)
    {
        return(0);
    }

    /* Assigning the ip address */
    if(final_ip)
    {
        os_strdup(ip_address, final_ip->ip);
    }

    if(*ip_address == '!')
    {
        ip_address++;
    }

    if(strcmp(ip_address, "any") == 0)
    {
        strcpy(ip_address, "::/0");   
    }

    /* Getting the cidr/netmask if available */
    tmp_str = strchr(ip_address,'/');
    if(tmp_str)
    {
        *tmp_str = '\0';
        tmp_str++;

        /* Cidr */
        if(strlen(tmp_str) <= 3)
        {
            cidr = atoi(tmp_str);
        }
        else
        {
            return(0);
        }
    }

    /* No cidr available */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(ip_address, NULL, &hints, &result) != 0)
    {
        return(0);
    }

    switch (result->ai_family)
    {
    case AF_INET:
        if (cidr >=0 && cidr <= 32)
        {
            prefixlength = cidr;
            break;
        }
        else if (cidr < 0)
        {
            prefixlength = 32;
            break;
        }
        return(0);
    case AF_INET6:
        if (cidr >=0 && cidr <= 128)
        {
            prefixlength = cidr;
            break;
        }
        else if (cidr < 0)
        {
            prefixlength = 128;
            break;
        }
        return(0);
    default:  
        return(0);
    }

    if (final_ip)
    {
        memcpy(&(final_ip->ss), result->ai_addr, result->ai_addrlen);
        final_ip->prefixlength = prefixlength;
    }

    freeaddrinfo(result);
    return((cidr >= 0) ? 2 : 1);
}


/** int sacmp(struct sockaddr *sa1, struct sockaddr *sa2, int prefixlength)
 * Compares two sockaddrs up to prefixlength.
 * Returns 0 if doesn't match or 1 if they do.
 */
int sacmp(struct sockaddr *sa1, struct sockaddr *sa2, int prefixlength)
{
    int _true = 1;
    int i, realaf1, realaf2;
    div_t ip_div;
    char *addr1, *addr2, modbits;

    switch (sa1->sa_family)
    {
    case AF_INET:
        addr1 = (char *) &(((struct sockaddr_in *) sa1)->sin_addr);
        realaf1 = AF_INET;
        break;
    case AF_INET6:
        addr1 = (char *) &(((struct sockaddr_in6 *) sa1)->sin6_addr);
        realaf1 = AF_INET6;
        if (IN6_IS_ADDR_V4MAPPED(addr1))
        {   /* shift the pointer for a mapped address */
            addr1 += (sizeof (struct in6_addr)) - (sizeof (struct in_addr));
            realaf1 = AF_INET;
        }
        break;
    default:
        return(!_true);
    }

    switch (sa2->sa_family)
    {
    case AF_INET:
        addr2 = (char *) &(((struct sockaddr_in *) sa2)->sin_addr);
        realaf2 = AF_INET;
        break;
    case AF_INET6:
        addr2 = (char *) &(((struct sockaddr_in6 *) sa2)->sin6_addr);
        realaf2 = AF_INET6;
        if (IN6_IS_ADDR_V4MAPPED(addr2))
        {   /* shift the pointer for a mapped address */
            addr1 += (sizeof (struct in6_addr)) - (sizeof (struct in_addr));
            realaf2 = AF_INET;
        }
        break;
    default:
        return(!_true);
    }

    if (realaf1 != realaf2)
    {
        return(!_true);
    }

    ip_div = div(prefixlength, 8);

    for (i=0; i < ip_div.quot; i++)
    {
        if (addr1[i] != addr2[i])
        {
            return(!_true);
        }
    }
    if (ip_div.rem)
    {
        modbits = ((char) ~0) << (8 - ip_div.rem);
        if ( (addr1[i] & modbits) != (addr2[i] & modbits) )
        {
            return(!_true);
        }
    }
    return(_true);
}


/** int OS_IsonTime(char *time_str, char *ossec_time)
 * Must be a valid string, called after OS_IsValidTime.
 * Returns 1 on success or 0 on failure.
 */
int OS_IsonTime(char *time_str, char *ossec_time)
{
    int _true = 1;

    if(*ossec_time == '!')
    {
        _true = 0;
    }
    ossec_time++;

    /* Comparing against min/max value */
    if((strncmp(time_str, ossec_time, 5) >= 0)&&
      (strncmp(time_str, ossec_time+5,5) <= 0))
    {
        return(_true);
    }

    return(!_true);
}


/** char *OS_IsValidTime(char *time_str)
 * Validates if a time is in an acceptable format
 * for ossec.
 * Returns 0 if doesn't match or a valid string for
 * ossec usage in success.
 * ** On success this function may modify the value of date
 * Acceptable formats:
 * hh:mm - hh:mm (24 hour format)
 * !hh:mm -hh:mm (24 hour format)
 * hh - hh (24 hour format)
 * hh:mm am - hh:mm pm (12 hour format)
 * hh am - hh pm (12 hour format)
 */
#define RM_WHITE(x)while(*x == ' ')x++;
char *__gethour(char *str, char *ossec_hour)
{
    int _size = 0;
    int chour = 0;
    int cmin = 0;

    /* Invalid time format */
    if(!isdigit((int)*str))
    {
        merror(INVALID_TIME, __local_name, str);
    }


    /* Hour */
    chour = atoi(str);


    /* Getting a valid hour */
    if(chour < 0 || chour >= 24)
    {
        merror(INVALID_TIME, __local_name, str);
        return(NULL);

    }

    /* Going after the hour */
    while(isdigit((int)*str))
    {
        _size++;
        str++;
    }

    /* Invalid hour */
    if(_size > 2)
    {
        merror(INVALID_TIME, __local_name, str);
        return(NULL);
    }


    /* Getting minute */
    if(*str == ':')
    {
        str++;
        if((!isdigit((int)*str)||
            !isdigit((int)*(str +1))) && isdigit((int)*(str +2)))
        {
            merror(INVALID_TIME, __local_name, str);
            return(NULL);
        }

        cmin = atoi(str);
        str+=2;
    }

    /* Removing spaces */
    RM_WHITE(str);

    if((*str == 'a') || (*str == 'A'))
    {
        str++;
        if((*str == 'm') || (*str == 'M'))
        {
            snprintf(ossec_hour, 6, "%02d:%02d", chour, cmin);
            str++;
            return(str);
        }
    }
    else if((*str == 'p') || (*str == 'P'))
    {
        str++;
        if((*str == 'm') || (*str == 'M'))
        {
            chour += 12;

            /* New hour must be valid */
            if(chour < 0 || chour >= 24)
            {
                merror(INVALID_TIME, __local_name, str);
                return(NULL);
            }

            snprintf(ossec_hour, 6, "%02d:%02d", chour, cmin);
            str++;
            return(str);
        }

    }
    else
    {
        snprintf(ossec_hour, 6, "%02d:%02d", chour, cmin);
        return(str);
    }

    /* Here is error */
    merror(INVALID_TIME, __local_name, str);
    return(NULL);
}


char *OS_IsValidTime(char *time_str)
{
    char *ret;
    char first_hour[7];
    char second_hour[7];
    int ng = 0;

    /* Must be not null */
    if(!time_str)
        return(NULL);


    /* Clearing memory */
    memset(first_hour, '\0', 7);
    memset(second_hour, '\0', 7);


    /* Removing white spaces */
    RM_WHITE(time_str);


    /* Checking for negative */
    if(*time_str == '!')
    {
        ng = 1;
        time_str++;

        /* We may have white spaces after the '!' */
        RM_WHITE(time_str);
    }


    /* Getting first hour */
    time_str = __gethour(time_str, first_hour);
    if(!time_str)
        return(NULL);

    /* Removing white spaces */
    RM_WHITE(time_str);

    if(*time_str != '-')
    {
        return(NULL);
    }

    time_str++;

    /* Removing white spaces */
    RM_WHITE(time_str);

    /* Getting second hour */
    time_str = __gethour(time_str, second_hour);
    if(!time_str)
        return(NULL);

    RM_WHITE(time_str);
    if(*time_str != '\0')
    {
        return(NULL);
    }

    os_calloc(13, sizeof(char), ret);

    /* Fixing dump hours */
    if(strcmp(first_hour,second_hour) > 0)
    {
        snprintf(ret, 12, "!%s%s", second_hour, first_hour);
        return(ret);
    }

    /* For the normal times */
    snprintf(ret, 12, "%c%s%s", ng == 0?'.':'!', first_hour, second_hour);
    return(ret);
}



/** int OS_IsAfterTime(char *time_str, char *ossec_time)
 *  Checks if the current time is the same or has passed the
 *  specified one.
 */
int OS_IsAfterTime(char *time_str, char *ossec_time)
{
    /* Unique times can't have a !. */
    if(*ossec_time == '!')
        return(0);


    ossec_time++;

    /* Comparing against min/max value */
    if(strncmp(time_str, ossec_time, 5) >= 0)
    {
        return(1);
    }

    return(0);
}



/** char *OS_IsValidUniqueTime(char *time_str)
 *  Creates a unique time, not a range. Must be used with OS_IsAfterTime.
 */
char *OS_IsValidUniqueTime(char *time_str)
{
    char mytime[128 +1];

    if(*time_str == '!')
        return(NULL);

    memset(mytime, '\0', 128 +1);
    snprintf(mytime, 128, "%s-%s", time_str, time_str);


    return(OS_IsValidTime(mytime));
}



/** int OS_IsonDay(int week_day, char *ossec_day)
 * Checks if the specified week day is in the
 * range.
 */
int OS_IsonDay(int week_day, char *ossec_day)
{
    int _true = 1;

    /* Negative */
    if(ossec_day[7] == '!')
        _true = 0;

    if(week_day < 0 || week_day > 7)
    {
        return(0);
    }

    /* It is on the right day */
    if(ossec_day[week_day] == 1)
        return(_true);

    return(!_true);
}



/** char *OS_IsValidDay(char *day_str)
 * Validates if an day is in an acceptable format
 * for ossec.
 * Returns 0 if doesn't match or a valid string for
 * ossec usage in success.
 * ** On success this function may modify the value of date
 * Acceptable formats:
 * weekdays, weekends, monday, tuesday, thursday,..
 * monday,tuesday
 * mon,tue wed
 */
#define RM_SEP(x)while((*x == ' ') || (*x == ','))x++;
#define IS_SEP(x) (*x == ' ' || *x == ',')
char *OS_IsValidDay(char *day_str)
{
    int i = 0, ng = 0;
    char *ret;
    char day_ret[9] = {0,0,0,0,0,0,0,0,0};
    char *(days[]) =
    {
        "sunday", "sun", "monday", "mon", "tuesday", "tue",
        "wednesday", "wed", "thursday", "thu", "friday",
        "fri", "saturday", "sat", "weekdays", "weekends", NULL
    };
    int days_int[] = {0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,8};

    /* Must be a valid string */
    if(!day_str)
        return(NULL);


    RM_WHITE(day_str);

    /* checking for negatives */
    if(*day_str == '!')
    {
        ng = 1;
        RM_WHITE(day_str);
    }

    while(*day_str != '\0')
    {
        i = 0;
        while(days[i])
        {
            if(strncasecmp(day_str, days[i], strlen(days[i])) == 0)
            {
                /* Weekdays */
                if(days_int[i] == 7)
                {
                    day_ret[1] = 1;
                    day_ret[2] = 1;
                    day_ret[3] = 1;
                    day_ret[4] = 1;
                    day_ret[5] = 1;
                }
                /* weekends */
                else if(days_int[i] == 8)
                {
                    day_ret[0] = 1;
                    day_ret[6] = 1;
                }
                else
                {
                    day_ret[days_int[i]] = 1;
                }
                break;
            }
            i++;
        }

        if(!days[i])
        {
            merror(INVALID_DAY, __local_name, day_str);
            return(NULL);
        }

        day_str += strlen(days[i]);

        if(IS_SEP(day_str))
        {
            RM_SEP(day_str);
            continue;
        }
        else if(*day_str == '\0')
            break;
        else
        {
            merror(INVALID_DAY, __local_name, day_str);
            return(NULL);
        }
    }

    /* Assigning values */
    os_calloc(9, sizeof(char), ret);
    if(ng == 1)
    {
        /* Setting nevative */
        ret[7] = '!';
    }

    ng = 0;
    for(i = 0;i<=6;i++)
    {
        /* Checking if some is checked */
        if(day_ret[i] == 1)
            ng = 1;
        ret[i] = day_ret[i];
    }

    /* At least one day must be checked */
    if(ng == 0)
    {
        free(ret);
        merror(INVALID_DAY, __local_name, day_str);
        return(NULL);
    }

    return(ret);
}

/* EOF */
