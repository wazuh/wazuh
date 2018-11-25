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

 #ifndef INTERNALOPTIONS_H
 #define INTERNALOPTIONS_H
 
typedef struct internal_option_t {
    char *name;
    int minimum;
    int maximum;
    int def;
    int value;
} internal_option_t;

/* Initialize internal options */
void internal_options_init();

/* Create internal option setting (setting name, minimum, maximum, default and current value) */
int internal_options_create(char *name, int minimum, int maximum, int def);

/* Get internal option value */
int internal_options_get(const char *name);

/* Set internal option value */
int internal_options_set(const char *name, int value);

/* Load local internal options () */
int internal_options_load_from_file();

/* Find the label array for an agent. Returns NULL if no such agent file found. */
//internal_option_t* get_internal_option(const char *key);

#endif
