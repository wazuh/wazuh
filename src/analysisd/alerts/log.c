/* @(#) $Id: ./src/analysisd/alerts/log.c, 2012/03/30 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */


#include "shared.h"
#include "log.h"
#include "alerts.h"
#include "getloglocation.h"
#include "rules.h"
#include "eventinfo.h"
#include "config.h"

#ifdef GEOIP
/* GeoIP Stuff */
#include "GeoIP.h"
#include "GeoIPCity.h"
#include <arpa/inet.h>

static const char * _mk_NA( const char * p ){
	return p ? p : "N/A";
}

/* check a.b.c.d is a private IP
 *      10.0.0.0        -   10.255.255.255  (10/8 prefix)
 * 	00001010.xxxxxxxx.xxxxxxxx.xxxxxxxx
 * 	0A.xx.xx.xx
 *      172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
 * 	10101100.0001xxxx.xxxxxxxx.xxxxxxxx
 * 	AC.1x.xxxx.xxxx
 *      192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
 * 	11000000.10101000.xxxxxxxx.xxxxxxxx
 * 	C0.A8.xx.xx
*/
static int _private_IP(char * ip) {
 #if HIGHFIRST
  #define PRIV10   0x0A000000
  #define MASK10   0xFF000000
  #define PRIV172  0xAC100000
  #define MASK172  0xFFF00000
  #define PRIV192  0xC0A80000
  #define MASK192  0xFFFF0000
 #else
  #define PRIV10   0x0000000A
  #define MASK10   0x000000FF
  #define PRIV172  0x000010AC
  #define MASK172  0x0000F0FF
  #define PRIV192  0x0000A8C0
  #define MASK192  0x0000FFFF
 #endif
	struct in_addr inp;
	if(inet_aton(ip, &inp)) { //non-zero if valid IP
		if ((inp.s_addr & MASK10) == PRIV10) return 1;
		if ((inp.s_addr & MASK172) == PRIV172) return 1;
		if ((inp.s_addr & MASK192) == PRIV192) return 1;
	}
	return 0;
}

/* GeoIPLookup */
/* Use the GeoIP API to locate an IP address
 */
char *GeoIPLookup(char *ip)
{
	GeoIP	*gi;
	GeoIPRecord	*gir;
	char buffer[OS_SIZE_1024 +1];

	/* Dump way to detect an IPv6 address */
	if (strchr(ip, ':')) {
		/* Use the IPv6 DB */
		gi = GeoIP_open(Config.geoip_db_path, GEOIP_INDEX_CACHE);
		if (gi == NULL) {
			merror(INVALID_GEOIP_DB, ARGV0, Config.geoip6_db_path);
			return("Unknown");
		}
		gir = GeoIP_record_by_name_v6(gi, (const char *)ip);
	}
	else if (strchr(ip, '.') && _private_IP(ip)) {
		return("");
	}
	else {
		/* Use the IPv4 DB */
		gi = GeoIP_open(Config.geoip_db_path, GEOIP_INDEX_CACHE);
		if (gi == NULL) {
			merror(INVALID_GEOIP_DB, ARGV0, Config.geoip_db_path);
			return("Unknown");
		}
		gir = GeoIP_record_by_name(gi, (const char *)ip);
	}
	if (gir != NULL) {
		sprintf(buffer,"%s,%s,%s",
				_mk_NA(gir->country_code),
				_mk_NA(GeoIP_region_name_by_code(gir->country_code, gir->region)),
				_mk_NA(gir->city)
		);
		GeoIP_delete(gi);
		return(buffer);
	}
	GeoIP_delete(gi);
	return("Unknown");
}
#endif /* GEOIP */

/* Drop/allow patterns */
OSMatch FWDROPpm;
OSMatch FWALLOWpm;


/* OS_Store: v0.2, 2005/02/10 */
/* Will store the events in a file 
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 *
 */
void OS_Store(Eventinfo *lf)
{
    if(strcmp(lf->location, "ossec-keepalive") == 0)
    {
        return;
    }
    if(strstr(lf->location, "->ossec-keepalive") != NULL)
    {
        return;
    }

    fprintf(_eflog,
            "%d %s %02d %s %s%s%s %s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->full_log);

    fflush(_eflog); 
    return;	
}



void OS_LogOutput(Eventinfo *lf)
{
#ifdef GEOIP
    char geoip_msg[OS_SIZE_1024 +1];
    geoip_msg[0] = '\0';
    if (Config.loggeoip && lf->srcip) {
 	strcpy(geoip_msg, GeoIPLookup(lf->srcip));
    }
#endif
    printf(
           "** Alert %d.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
            lf->time,
            __crt_ftell,
            lf->generated_rule->alert_opts & DO_MAILALERT?" mail ":"",
            lf->generated_rule->group,
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->generated_rule->sigid,
            lf->generated_rule->level,
            lf->generated_rule->comment,

            lf->srcip == NULL?"":"\nSrc IP: ",
            lf->srcip == NULL?"":lf->srcip,

#ifdef GEOIP
            (strlen(geoip_msg) == 0)?"":"\nSrc Location: ",
            (strlen(geoip_msg) == 0)?"":geoip_msg,
#else
	    "",
            "",
#endif

            lf->srcport == NULL?"":"\nSrc Port: ",
            lf->srcport == NULL?"":lf->srcport,

            lf->dstip == NULL?"":"\nDst IP: ",
            lf->dstip == NULL?"":lf->dstip,

            lf->dstport == NULL?"":"\nDst Port: ",
            lf->dstport == NULL?"":lf->dstport,

            lf->dstuser == NULL?"":"\nUser: ",
            lf->dstuser == NULL?"":lf->dstuser,

            lf->full_log);


    /* Printing the last events if present */
    if(lf->generated_rule->last_events)
    {
        char **lasts = lf->generated_rule->last_events;
        while(*lasts)
        {
            printf("%.1256s\n",*lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    printf("\n");

    fflush(stdout);
    return;	
}



/* OS_Log: v0.3, 2006/03/04 */
/* _writefile: v0.2, 2005/02/09 */
void OS_Log(Eventinfo *lf)
{
#ifdef GEOIP
    char geoip_msg[OS_SIZE_1024 +1];
    geoip_msg[0] = '\0';
    if (Config.loggeoip && lf->srcip) {
 	strcpy(geoip_msg, GeoIPLookup(lf->srcip));
    }
#endif
    /* Writting to the alert log file */
    fprintf(_aflog,
            "** Alert %d.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
            lf->time,
            __crt_ftell,
            lf->generated_rule->alert_opts & DO_MAILALERT?" mail ":"",
            lf->generated_rule->group,
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->generated_rule->sigid,
            lf->generated_rule->level,
            lf->generated_rule->comment,

            lf->srcip == NULL?"":"\nSrc IP: ",
            lf->srcip == NULL?"":lf->srcip,

#ifdef GEOIP
            (strlen(geoip_msg) == 0)?"":"\nSrc Location: ",
            (strlen(geoip_msg) == 0)?"":geoip_msg,
#else
            "",
            "",
#endif

            lf->srcport == NULL?"":"\nSrc Port: ",
            lf->srcport == NULL?"":lf->srcport,

            lf->dstip == NULL?"":"\nDst IP: ",
            lf->dstip == NULL?"":lf->dstip,

            lf->dstport == NULL?"":"\nDst Port: ",
            lf->dstport == NULL?"":lf->dstport,

            lf->dstuser == NULL?"":"\nUser: ",
            lf->dstuser == NULL?"":lf->dstuser,

            lf->full_log);


    /* Printing the last events if present */
    if(lf->generated_rule->last_events)
    {
        char **lasts = lf->generated_rule->last_events;
        while(*lasts)
        {
            fprintf(_aflog,"%.1256s\n",*lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    fprintf(_aflog,"\n");

    fflush(_aflog);
    return;	
}



void OS_InitFwLog()
{
    /* Initializing fw log regexes */
    if(!OSMatch_Compile(FWDROP, &FWDROPpm, 0))
    {
        ErrorExit(REGEX_COMPILE, ARGV0, FWDROP,
                FWDROPpm.error);
    }

    if(!OSMatch_Compile(FWALLOW, &FWALLOWpm, 0))
    {
        ErrorExit(REGEX_COMPILE, ARGV0, FWALLOW,
                FWALLOWpm.error);
    }
                    
}


/* FW_Log: v0.1, 2005/12/30 */
int FW_Log(Eventinfo *lf)
{
    /* If we don't have the srcip or the
     * action, there is no point in going
     * forward over here
     */
    if(!lf->action || !lf->srcip)
    {
        return(0);
    }


    /* Setting the actions */
    switch(*lf->action)
    {
        /* discard, drop, deny, */
        case 'd':
        case 'D':
        /* reject, */
        case 'r':
        case 'R':
        /* block */
        case 'b':
        case 'B':
            os_free(lf->action);
            os_strdup("DROP", lf->action);
            break;
        /* Closed */
        case 'c':
        case 'C':
        /* Teardown */
        case 't':
        case 'T':
            os_free(lf->action);
            os_strdup("CLOSED", lf->action);
            break;
        /* allow, accept, */    
        case 'a':
        case 'A':
        /* pass/permitted */
        case 'p':
        case 'P':
        /* open */
        case 'o':
        case 'O':    
            os_free(lf->action);
            os_strdup("ALLOW", lf->action);        
            break;
        default:
            if(OSMatch_Execute(lf->action,strlen(lf->action),&FWDROPpm))
            {
                os_free(lf->action);
                os_strdup("DROP", lf->action);
            }
            if(OSMatch_Execute(lf->action,strlen(lf->action),&FWALLOWpm))
            {
                os_free(lf->action);
                os_strdup("ALLOW", lf->action);
            }
            else
            {
                os_free(lf->action);
                os_strdup("UNKNOWN", lf->action);
            }
            break;    
    }


    /* log to file */
    fprintf(_fflog,
            "%d %s %02d %s %s%s%s %s %s %s:%s->%s:%s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->action,
            lf->protocol,
            lf->srcip,
            lf->srcport,
            lf->dstip,
            lf->dstport);
    
    fflush(_fflog);

    return(1);
}

/* EOF */
