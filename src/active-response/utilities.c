

#include "utilities.h"
#include <stddef.h>
#include "active_responses.h"



char* splitStrFromCharDelimiter(const char * output_buf, const char delimiter, char * strBefore, char *strAfter){
    char* retVal = NULL;
    char *pos = NULL;

    if (output_buf != NULL) {
        pos = strchr(output_buf, delimiter);
        retVal = pos;
        if (strBefore != NULL){
            strncpy(strBefore, output_buf, pos - output_buf);
        }
        if (strAfter != NULL){
            strncpy(strAfter, pos + 1, strlen(pos)); 
        }

    }
    return  retVal;
}

int isEnabledFromPattern(const char * output_buf, const char * str_pattern_1, const char * str_pattern_2){
    int retVal = 0;
    const char *pos = NULL;
    if (str_pattern_1 != NULL) {
        pos = strstr(output_buf, str_pattern_1);
    }

    if (pos != NULL) {
        char state[OS_MAXSTR];
        char buffer[OS_MAXSTR];
        if (str_pattern_2 != NULL) {
            snprintf(buffer, OS_MAXSTR -1 , "%%*s %%%ds", strlen(str_pattern_2));
            if (pos && sscanf(pos, buffer /*"%*s %7s"*/, state) == 1) {
                if (strcmp(state, str_pattern_2) == 0) {
                    retVal = 1;
                } else {
                    retVal = 0;
                }
            }
        } else {
            retVal = 1;
        }
    }
    return  retVal;
}

#ifdef WIN32

void getFirewallProfile(const char * output_buf, firewallData_t *firewallData){
    if( output_buf != NULL){
        const char* ptr = NULL;
        if ((ptr = strstr(output_buf, "FirewallPolicy")) != NULL) {
           char after[OS_MAXSTR];
           splitStrFromCharDelimiter(ptr, '\\', NULL, after);
           
            if (after != NULL){
                if (strstr(after, "DomainProfile") != NULL){
                    firewallData->profile = FIREWALL_DOMAIN;
                    firewallData->isThereProfile = true;
                } else if (strstr(after, "PublicProfile") != NULL){
                    firewallData->profile = FIREWALL_PUBLIC;
                    firewallData->isThereProfile = true;
                } else if (strstr(after, "StandardProfile") != NULL){
                    firewallData->profile = FIREWALL_PRIVATE;
                    firewallData->isThereProfile = true;
                } else {
                    firewallData->isThereProfile = false;
                }
            }
        }
    }
}

void getStatusFirewallProfile(const char * output_buf, firewallData_t *firewallData){
    if (firewallData->isThereProfile == true && isEnabledFromPattern(output_buf, "REG_DWORD", "0x1")) {
        firewallData->isEnabled = true;
    }
    else {
        firewallData->isEnabled = false;
    }
}

#endif /*WIN32*/
