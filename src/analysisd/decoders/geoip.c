/* @(#) $Id: ./src/analysisd/decoders/geoip.c, 2014/03/08 dcid Exp $
 */

/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2014 Daniel Cid
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* GeoIP - Every IP address will have its geolocation added to it */

#ifdef LIBGEOIP_ENABLED


#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "GeoIP.h"
#include "GeoIPCity.h"


char *GetGeoInfobyIP(char *ip_addr)
{
    GeoIPRecord *geoiprecord;
    char *geodata = NULL;
    char geobuffer[256 +1];

    if(!geoipdb)
    {
        return(NULL);
    }

    if(!ip_addr)
    {
        return(NULL);
    }

    geoiprecord = GeoIP_record_by_name(geoipdb, (const char *)ip_addr);
    if(geoiprecord == NULL)
    {
        return(NULL);
    }

    if(geoiprecord->country_code == NULL)
    {
        GeoIPRecord_delete(geoiprecord);
        return(NULL);
    }

    if(strlen(geoiprecord->country_code) < 2)
    {
        GeoIPRecord_delete(geoiprecord);
        return(NULL);
    }


    if(geoiprecord->region != NULL && geoiprecord->region[0] != '\0')
    {
        const char *regionname = NULL;
        regionname = GeoIP_region_name_by_code(geoiprecord->country_code, geoiprecord->region);
        if(regionname != NULL)
        {
            snprintf(geobuffer, 255, "%s / %s", geoiprecord->country_code, regionname);
            geobuffer[255] = '\0';
            geodata = strdup(geobuffer);
        }
        else
        {
            geodata = strdup(geoiprecord->country_code);
        }
    }
    else
    {
        geodata = strdup(geoiprecord->country_code);
    }

    GeoIPRecord_delete(geoiprecord);
    return(geodata);

}

#endif
