/*  $OSSEC, validate_op.c, v0.1, 2006/01/24, Daniel B. Cid$  */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS.
 * Available at http://www.ossec.net/hids/
 */

/* Functions to validate values */


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
    char buf[OS_MAXSTR +1];
    char *buf_pt;
    char *tmp_buffer;
    char *ret;
    
    fp = fopen(OSSEC_DEFINES, "r");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, OSSEC_DEFINES);
        return(NULL);
    }

    /* Invalid call */
    if(!high_name || !low_name)
    {
        merror(NULL_ERROR, ARGV0);
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
            merror(FGETS_ERROR, ARGV0, OSSEC_DEFINES, buf);
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
            merror(FGETS_ERROR, ARGV0, OSSEC_DEFINES, buf);
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
        ErrorExit(DEF_NOT_FOUND, ARGV0, high_name, low_name);
    }

    pt = value;
    while(*pt != '\0')
    {
        if(!isdigit(*pt))
        {
            ErrorExit(INV_DEF, ARGV0, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if((ret < min) || (ret > max))
    {
        ErrorExit(INV_DEF, ARGV0, high_name, low_name, value);
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


/* EOF */
