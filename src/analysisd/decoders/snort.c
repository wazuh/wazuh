/*   $OSSEC, snort.c, v0.2, 2005/08/26, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.2(2005/08/26): Fixing the decoder for snort-fast alerts
 * v0.1:
 */

/* Snort decoder */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "analysisd/eventinfo.h"
#include "os_regex/os_regex.h"
#include "headers/mq_op.h"


/* Special decoder for snort
 * We are not using the default rendering
 * to make it simple (and less resource intensive)
 */
int DecodeSnort(Eventinfo *lf, char c)
{
    char **ret = NULL;
    
    #ifdef DEBUG
    printf("%s: DEBUG: Checking snort decoder.\n",ARGV0);
    #endif


    /* Some examples
       [**] [1:1054:7] WEB-MISC weblogic/tomcat .jsp view source attempt [**] 
       [Classification: Web Application Attack] 
       [Priority: 1]  10.4.12.26:34041 -> 66.179.53.37:80

       [**] [1:1421:11] SNMP AgentX/tcp request [**] 
       [Classification: Attempted Information Leak] [Priority: 2]  
       10.4.3.20:626 -> 10.4.10.161:705

       [**] [1:1882:10] ATTACK-RESPONSES id check returned userid [**] 
       [Classification: Potentially Bad Traffic] [Priority: 2] 
       {UDP} 192.168.20.32 -> 192.168.20.2
     */

    /* from syslog
      Aug 26 17:30:34 niban snort: [1:469:3] ICMP PING NMAP [Classification: Attempted Information Leak] [Priority: 2]: {ICMP} 10.4.12.26 -> 10.4.10.231
      Aug 26 17:30:34 niban snort: [1:408:5] ICMP Echo Reply [Classification: Misc Activity] [Priority: 3]: {ICMP} 10.4.10.231 -> 10.4.12.26
      Aug 26 17:30:35 niban snort: [1:1420:11] SNMP trap tcp [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37020 -> 10.4.10.231:162
      Aug 26 17:30:36 niban snort: [1:1420:11] SNMP trap tcp [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37021 -> 10.4.10.231:162
      Aug 26 17:30:40 niban snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.11.94:669 -> 10.4.3.20:111
      Aug 26 17:30:40 niban snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.11.94:669 -> 10.4.3.20:111
      Aug 26 17:30:40 niban snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.11.94:670 -> 10.4.3.20:111
      Aug 26 17:30:40 niban snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.11.94:670 -> 10.4.3.20:111
      Aug 26 17:30:42 niban snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.10.231:858 -> 10.4.3.20:111
      Aug 26 17:30:44 niban snort: [1:590:12] RPC portmap ypserv request UDP [Classification: Decode of an RPC Query] [Priority: 2]: {UDP} 10.4.10.231:858 -> 10.4.3.20:111
      Aug 26 17:30:44 niban snort: [1:1421:11] SNMP AgentX/tcp request [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37020 -> 10.4.10.231:705
      Aug 26 17:30:44 niban snort: [1:1421:11] SNMP AgentX/tcp request [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37021 -> 10.4.10.231:705
      Aug 26 17:30:52 niban snort: [1:1418:11] SNMP request tcp [Classification: Attempted Information Leak] [Priority: 2]: {TCP} 10.4.12.26:37020 -> 10.4.10.231:161
     */
     
    /* setting snort ID */
    lf->type = SNORT;
  
    if(c == SNORT_MQ_FULLC)
    {
        ret = OS_RegexStr("^[**] [(\\d+:\\d+:\\d+)]\\.+[Priority: \\d+]  "
             "(\\S+):\\d+ ->", lf->log);          
    }

    else if(c == SNORT_MQ_FASTC)
    {
       ret = OS_RegexStr("^[**] [(\\d+:\\d+:\\d+)]\\.+[Priority: \\d+] "
            "{\\S+} (\\S+):\\d+ ->", lf->log); 
    }
    
    else if(c == 0)
    {
        /* snort from syslog */
        ret = OS_RegexStr("^snort: [(\\d+:\\d+:\\d+)]\\.+[Priority: \\d+]: "
            "{\\S+} (\\S+):\\d+ ->", lf->log);
    }
    
    /* Didn't match */
    if(ret == NULL)
        return(0);
   
     
    if(ret[0])
    {
        lf->id = strdup(ret[0]);
        free(ret[0]);
    }
    
    if(ret[1])
    {
        lf->srcip = strdup(ret[1]);
        free(ret[1]);
    }
    
    free(ret); 

    /* Snort FTS */
    lf->fts = strdup("name,id,srcip");
    lf->comment = strdup("First time Snort rule fired");
    

    return(1);
}
