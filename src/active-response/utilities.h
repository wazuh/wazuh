#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/**
 * @brief enumeration of the available profiles
 */
typedef enum {
    FIREWALL_DOMAIN = 0,
    FIREWALL_PRIVATE,
    FIREWALL_PUBLIC,
    FIREWALL_DEFAULT
} firewallProfile_t;

/**
 * @brief firewall data struct
 */
typedef struct{
    bool isThereProfile;
    bool isEnabled;
    firewallProfile_t profile;
} firewallData_t;
#define FIREWALL_DATA_INITIALIZE {false, false, FIREWALL_DOMAIN}
#define FIREWALL_PROFILES_MAX (3) /*!< Maximun number of profiles*/


/** 
 * @brief this function split string
 * @param output_buf buffer output
 * @param delimiter  delimiter with which want to split string
 * @param strBefore  buffer to store split string
 * @param strAfter   buffer to store split string
 * @return pointer to delimiter or NULL if no found
*/
char* splitStrFromCharDelimiter(const char * output_buf, const char delimiter, char * strBefore, char *strAfter);

/**
 * @brief search a pair pattern1 and after pattern2 only with space at middle
 * @param output_buf buffer where search
 * @param str_pattern_1 pattern search to match
 * @param str_pattern_2 pattern search to match
 * @return 1 or 0 
 * @example retVal = isEnabledFromPattern(output_buf, "Status: ", "Enabled");
 *          if for example with "Status :    Enabled" than pattern1:"Status :" find "Enabled", its return 1.
 * 
 *          retVal = isEnabledFromPattern(output_buf, "Status: ", NULL)  its find only "Status"
*/
int isEnabledFromPattern(const char * output_buf, const char * str_pattern_1, const char * str_pattern_2);


#ifdef WIN32
/** 
 * @brief this function get name and if is there profile
 * @param output_buf buffer output
 * @param firewallData  pointer to firewall data
*/
void getFirewallProfile(const char * output_buf, firewallData_t *firewallData);

/** 
 * @brief this function get status profile
 * @param output_buf buffer output
 * @param firewallData  pointer to firewall data
*/
void getStatusFirewallProfile(const char * output_buf, firewallData_t *firewallData);


#endif /*WIN32*/

#ifdef __cplusplus
}
#endif 
#endif  /*_UTILITIES_H_*/