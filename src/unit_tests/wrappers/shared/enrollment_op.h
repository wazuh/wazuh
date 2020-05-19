/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_ENROLLMENT_OP
#define UNIT_TEST_WRAPPERS_ENROLLMENT_OP

// Since windows version gethostname is linked dinamically,
// will wrap both os_vesions the same way
int wrap_enrollment_op_gethostname(char *name, int len);

int wrap_enrollment_op_fprintf ( FILE * stream, const char * format, ... );

extern int flag_fopen;
#endif //UNIT_TEST_WRAPPERS_ENROLLMENT_OP
