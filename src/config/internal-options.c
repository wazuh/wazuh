/*
* Internal options settings
* Copyright (C) 2017 Wazuh Inc.
* Nov 24, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #include "shared.h"
 #include "internal-options.h"
 #include "config.h"


static OSHash *internal_options;

/* Initialize internal options */
void internal_options_init(){
  
      internal_options = OSHash_Create();
      internal_options_create("analysisd.min_rotate_interval", 10, 86400, 600);  
      internal_options_create("analysisd.state_interval", 0, 86400, 5);
      internal_options_create("syscheck.sleep", 0, 100, 784);
      internal_options_create("syscheck.sleep_after", 1, 500, 100);
      internal_options_create("agent.debug", 0, 2, 0);
      
      internal_options_load_from_file();
}

/* Create internal option: Setting name, minimum value, maximum value, default value and current value.
* Return: 0 success. 1 failure.
* Arguments: Setting name
*/
int internal_options_create(char *name, int minimum, int maximum, int def)
{
  
    internal_option_t *setting;
    os_calloc(1, sizeof(internal_option_t), setting);
    setting->minimum = minimum;
    setting->maximum = maximum;
    setting->def = def;
    setting->value = def;
    setting->name = name;
    if (OSHash_Add(internal_options, setting->name, setting) != 2) {
        merror_exit("Could not create internal option '%s'", name);
        return 1;
    }
    return 0;
}

/* Get internal option value
* Return: Internal option value. -1 on failure.
* Arguments: Setting name
*/
int internal_options_get(const char *name)
{
    internal_option_t *setting;
    if (setting = (internal_option_t*)OSHash_Get(internal_options, name), !setting)
    {
      merror_exit("Could not get internal option '%s'", name);
      return -1;
    }else{
      return setting->value;
    }
}

/* Set internal option value. Check new value is valid according min/max limits.
 * Return: 0 success. 1 failure.
 * Arguments: Setting name, value
 */
int internal_options_set(const char *name, int value)
{
  internal_option_t *setting;
  if (setting = (internal_option_t*)OSHash_Get(internal_options, name), !setting)
  {
    merror_exit("Could not get internal option '%s'", name);
    return 1;  
  }else{
    // Validate new value is between min/max limits.
    if ((value < setting->minimum) || (value > setting->maximum)) {
        merror_exit("Could not set internal option '%s' to value '%d' (Minimum allowed value: %d. Maximum allowed value: %d)", name, value, setting->minimum, setting->maximum);
        return 1;
    }
    setting->value = value;
    if (!OSHash_Update(internal_options, name, setting))
    {
        merror_exit("Could not set internal option '%s' to value '%d'", name, value);
        return 1;
    }
    return 0;
  }
}

/* Load internal options from file. It will overwrite default values.
 * Return: 0 success. 1 failure.
 */
int internal_options_load_from_file(){
    FILE *fp;
    char def_file[OS_FLSIZE + 1];
    char buf[OS_SIZE_1024 + 1];
    char *buf_pt;
    char *tmp_buffer;
    char *setting_value;
    char *setting_name;
    int i;
    

#ifndef WIN32
    if (isChroot()) {
        snprintf(def_file, OS_FLSIZE, "%s", OSSEC_LDEFINES);
    } else {
        snprintf(def_file, OS_FLSIZE, "%s%s", DEFAULTDIR, OSSEC_LDEFINES);
    }
#else
    snprintf(def_file, OS_FLSIZE, "%s", OSSEC_LDEFINES);
#endif

    fp = fopen(def_file, "r");
    if (!fp) {
        if (strcmp(OSSEC_LDEFINES, OSSEC_LDEFINES) != 0) {
            merror(FOPEN_ERROR, def_file, errno, strerror(errno));
        }
        return (1);
    }

    /* Read it */
    buf[OS_SIZE_1024] = '\0';
    while (fgets(buf, OS_SIZE_1024 , fp) != NULL) {
        /* Commented or blank lines */
        if (buf[0] == '#' || buf[0] == ' ' || buf[0] == '\n') {
            continue;
        }

        /* Messages not formatted correctly */
        buf_pt = strchr(buf, '=');
        if (!buf_pt) {
            merror(FGETS_ERROR, def_file, buf);
            continue;
        }
        *buf_pt = '\0';
        buf_pt++;
        os_strdup(buf, setting_name);

        tmp_buffer = buf_pt;
        /* Remove possible whitespaces between the low name and the equal sign */
        i = (strlen(tmp_buffer) - 1);
        while(tmp_buffer[i] == ' ')
        {
            tmp_buffer[i] = '\0';
            i--;
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
        
        os_strdup(buf_pt, setting_value);
        
        // Set the setting value
        internal_options_set(setting_name, atoi(setting_value));
    }

    fclose(fp);
    return 0;
}