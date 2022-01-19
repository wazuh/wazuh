/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "test_fim.h"

void expect_fim_diff_delete_compress_folder(struct dirent *dir) {
    expect_any(__wrap_IsDir, file);
    will_return(__wrap_IsDir, 0);

    expect_any(__wrap_DirSize, path);
    will_return(__wrap_DirSize, 0);

    expect_any(__wrap_rmdir_ex, name);
    will_return(__wrap_rmdir_ex, 0);
    expect_any(__wrap__mdebug2, formatted_msg);

    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, dir);
    will_return(__wrap_readdir, NULL);
}
