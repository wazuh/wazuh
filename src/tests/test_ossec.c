/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdlib.h>

#include "test_os_zlib.h"
#include "test_os_xml.h"

int main(void)
{
	SRunner *sr = srunner_create(test_os_zlib_suite());
	srunner_add_suite(sr, test_os_xml_suite());
	srunner_run_all(sr, CK_NORMAL);
	int number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return ((number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}
