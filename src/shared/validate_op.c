/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
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
     "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/?[0-9]{0,2}$";


/* Read the file and return a string the matches the following
 * format: high_name.low_name.
 * If return is not null, value must be free.
 */
static char *_read_file(char *high_name, char *low_name)
{
    FILE *fp;
    char def_file[OS_MAXSTR +1];
    char buf[OS_MAXSTR +1];
    char *buf_pt;
    char *tmp_buffer;
    char *ret;
    
    if(isChroot())
    {
        snprintf(def_file,OS_MAXSTR,"%s", OSSEC_DEFINES);
    }
    else
    {
        snprintf(def_file,OS_MAXSTR,"%s%s",DEFAULTDIR, OSSEC_DEFINES);
    }
                                                        
    fp = fopen(def_file, "r");
    if(!fp)
    {
        merror(FOPEN_ERROR, __local_name, def_file);
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
    while(fgets(buf, OS_MAXSTR , fp) != NULL)
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

    value = _read_file(high_name, low_name);
    if(!value)
    {
        ErrorExit(DEF_NOT_FOUND, __local_name, high_name, low_name);
    }

    pt = value;
    while(*pt != '\0')
    {
        if(!isdigit(*pt))
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


     
/** int OS_IPFound(char *ip_address, char *that_ip)
 * Checks if ip_address is present at that_ip.
 * Returns 1 on success or 0 on failure.
 */
int OS_IPFound(char *ip_address, char *that_ip)
{
    int _true = 1;
    
    /* If negate is set */
    if(*that_ip == '!')
    {
        that_ip++;
        _true = 0;
    }
    
    if(*that_ip == '.')
    {
        if(strncmp(ip_address, that_ip+1, strlen(that_ip)-1) == 0)
        {
            /* found */
            return(_true);
        }
    }
    else
    {
        if(strcmp(ip_address, that_ip) == 0)
        {
            /* found */
            return(_true);
        }
    }
    
    return(!_true);
}

     
/** int OS_IPFoundList(char *ip_address, char **list_of_ips)
 * Checks if ip_address is present on the "list_of_ips".
 * Returns 1 on success or 0 on failure.
 * The list MUST be NULL terminated
 */
int OS_IPFoundList(char *ip_address, char **list_of_ips)
{
    int _true = 1;
    int _extra = 0;
    
    while(*list_of_ips)
    {
        _extra = 0;
        
        if(**list_of_ips == '!')
        {
            _true = 0;
            _extra++;
        }
        
        if(**list_of_ips == '.')
        {
            _extra++;
            if(strncmp(ip_address, 
                      (*list_of_ips) + _extra, 
                      strlen(*list_of_ips) - _extra) == 0)
            {
                /* found */
                return(_true);
            }
        }
        else
        {
            if(strcmp(ip_address, (*list_of_ips) + _extra) == 0)
            {
                /* found */
                return(_true);
            }
        }
        list_of_ips++;
    }

    return(!_true);
}    

     
/** int OS_HasNetmask(char *ip)
 * Checks if an IP Address has a netmask or not.
 * This function must ONLY be called after "OS_IsValidIP"
 */
int OS_HasNetmask(char *ip_address)
{
    if(*ip_address == '!')
        ip_address++;
    
    if(ip_address[0] == '.')
    {
        return(1);
    }

    return(0);
}    



/** int OS_IsValidIP(char *ip)
 * Validates if an ip address is in the right
 * format.
 * Returns 0 if doesn't match or 1 if it does.
 * ** On success this function may modify the value of ip_address
 */
int OS_IsValidIP(char *ip_address)
{
    int cidr = 0;
    int i = 0;
    int ip_address_size;
    
    int ip_parts[4];
    char *tmp_str;

    /* Can't be null */
    if(!ip_address)
    {
        return(0);
    }

    if(*ip_address == '!')
    {
        ip_address++;
    }
   
    #ifndef WIN32 
    /* checking against the basic regex */
    if(!OS_PRegex(ip_address, ip_address_regex))
    {
        return(0);
    }
    #else
    {
        char *tmp_ip;
        int dots = 0;
        tmp_ip = ip_address;
        while(*tmp_ip != '\0')
        {
            if(*tmp_ip < '0'  && 
               *tmp_ip > '9'  && 
               *tmp_ip != '.' &&
               *tmp_ip != '/')
            {
                /* Invalid ip */
                return(0);
            }
            if(*tmp_ip == '.')
                dots++;
            tmp_ip++;
        }
        if(dots != 3)
            return(0);
    }
    #endif

    
    /* Getting the size of ip_address */
    ip_address_size = strlen(ip_address);
    
    
    /* Getting the cidr if available */ 
    tmp_str = strchr(ip_address,'/');
    if(tmp_str)
    {
        tmp_str++;
        cidr = atoi(tmp_str);

        /* The CIDR can onlu be from 8,16,24 to 32 */
        if((cidr != 8) && (cidr != 16) && (cidr != 24) && (cidr != 32))
        {
            return(0);
        }

        /* Only one IP */
        if(cidr == 32)
        {
            tmp_str--;*tmp_str = '\0';
            cidr = 0;
        }
    }

    /* Setting tmp_str to the beginning of the ip */
    tmp_str = ip_address;

    
    /* Getting each part of the IP */
    while(i <= 3)
    {
        ip_parts[i] = atoi(tmp_str);
        
        if((ip_parts[i] > 255) || (ip_parts[i] < 0))
        {
            return(0);
        }
        
        /* Jumping to the next part of the ip */
        tmp_str = strchr(tmp_str, '.');
        if(tmp_str)
        {
            tmp_str++;
        }
        else
        {
            if(i != 3)
            {
                return(0);
            }
            break;
        }
        i++;
    }

    /* Getting the CIDRs */
    if(cidr && (cidr == 8))
    {
        snprintf(ip_address, ip_address_size, ".%d.",
                                              ip_parts[0]);
    }
    else if(cidr && (cidr == 16))
    {
        snprintf(ip_address, ip_address_size, ".%d.%d.",
                                              ip_parts[0],
                                              ip_parts[1]);
    }
    else if(cidr && (cidr == 24))
    {
        snprintf(ip_address, ip_address_size, ".%d.%d.%d.",
                                              ip_parts[0],
                                              ip_parts[1],
                                              ip_parts[2]);  
    }
    
    
    /* Returning success */
    return(1);
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
    if(!isdigit(*str))
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
    while(isdigit(*str))
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
        if((!isdigit(*str) || !isdigit(*(str +1)))&& isdigit(*(str +2)))
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
            merror(INVALID_DAY, ARGV0, day_str);
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
            merror(INVALID_DAY, ARGV0, day_str);
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
        merror(INVALID_DAY, ARGV0, day_str);
        return(NULL);
    }
    
    return(ret);
}

/* EOF */
