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
#include <stdio.h>

#include "../../headers/shared.h"
#include "../../analysisd/system_memory.h"

bool w_cgroup_has_controller(const char *controllers, const char *controller);

/* setup/teardown */

/* Each test builds a fake cgroup hierarchy in a temporary directory */
static int setup_cgroup_root(void **state) {
    char *root;
    os_strdup("/tmp/wazuh_cgroup_test_XXXXXX", root);

    if (mkdtemp(root) == NULL) {
        os_free(root);
        return -1;
    }

    *state = root;
    return 0;
}

static int teardown_cgroup_root(void **state) {
    char *root = *state;
    rmdir_ex(root);
    os_free(root);
    return 0;
}

/* helpers */

/* Write content to root/relative_path, creating the missing directories */
static void write_file(const char *root, const char *relative_path, const char *content) {
    char path[PATH_MAX];
    char *slash;

    snprintf(path, sizeof(path), "%s/%s", root, relative_path);

    for (slash = strchr(path + strlen(root) + 1, '/'); slash != NULL; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        mkdir(path, 0700);
        *slash = '/';
    }

    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static uint64_t cgroup_limit(const char *root) {
    char proc_cgroup[PATH_MAX];
    char proc_mountinfo[PATH_MAX];

    snprintf(proc_cgroup, sizeof(proc_cgroup), "%s/proc_self_cgroup", root);
    snprintf(proc_mountinfo, sizeof(proc_mountinfo), "%s/proc_self_mountinfo", root);

    // Mount points in mountinfo are created under root
    return w_get_cgroup_memory_limit(proc_cgroup, proc_mountinfo, root);
}

#define MOUNT_V2            "35 24 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 " \
                            "rw,nsdelegate\n"
#define MOUNT_V2_UNIFIED    "36 24 0:31 / /sys/fs/cgroup/unified rw,nosuid shared:10 - cgroup2 cgroup2 rw\n"
#define MOUNT_V1_CPU        "39 30 0:34 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid shared:19 - cgroup cgroup rw,cpu,cpuacct\n"

/* tests */

void test_w_get_physical_memory(void **state) {
    assert_true(w_get_physical_memory() > 0);
}

void test_w_get_memory_size(void **state) {
    bool cgroup_limited = true;
    uint64_t memory = w_get_memory_size(&cgroup_limited);

    assert_true(memory > 0);
    assert_true(memory <= w_get_physical_memory());
    assert_true(cgroup_limited || memory == w_get_physical_memory());
}

void test_cgroup_v2_own_limit(void **state) {
    char *root = *state;

    write_file(root, "proc_self_cgroup", "0::/system.slice/wazuh-manager.service\n");
    write_file(root, "proc_self_mountinfo", MOUNT_V2);
    write_file(root, "sys/fs/cgroup/system.slice/wazuh-manager.service/memory.max", "2147483648\n");
    write_file(root, "sys/fs/cgroup/system.slice/memory.max", "max\n");

    assert_int_equal(cgroup_limit(root), 2147483648ULL);
}

void test_cgroup_v2_ancestor_limit(void **state) {
    char *root = *state;

    // The lowest limit of the hierarchy applies, even if it is set on an ancestor
    write_file(root, "proc_self_cgroup", "0::/system.slice/wazuh-manager.service\n");
    write_file(root, "proc_self_mountinfo", MOUNT_V2);
    write_file(root, "sys/fs/cgroup/system.slice/wazuh-manager.service/memory.max", "max\n");
    write_file(root, "sys/fs/cgroup/system.slice/memory.max", "1073741824\n");

    assert_int_equal(cgroup_limit(root), 1073741824ULL);
}

void test_cgroup_v2_no_limit(void **state) {
    char *root = *state;

    write_file(root, "proc_self_cgroup", "0::/init\n");
    write_file(root, "proc_self_mountinfo", MOUNT_V2);
    write_file(root, "sys/fs/cgroup/init/memory.max", "max\n");

    assert_int_equal(cgroup_limit(root), 0);
}

void test_cgroup_v2_container_root(void **state) {
    char *root = *state;

    // With a private cgroup namespace, the process is at the root of the hierarchy
    write_file(root, "proc_self_cgroup", "0::/\n");
    write_file(root, "proc_self_mountinfo", MOUNT_V2);
    write_file(root, "sys/fs/cgroup/memory.max", "536870912\n");

    assert_int_equal(cgroup_limit(root), 536870912ULL);
}

void test_cgroup_v2_mounted_subtree(void **state) {
    char *root = *state;

    // The mount exposes /docker/abc: the service limit is in "service" under the mount point, not in the root
    write_file(root, "proc_self_cgroup", "0::/docker/abc/service\n");
    write_file(root, "proc_self_mountinfo",
               "35 24 0:30 /docker/abc /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n");
    write_file(root, "sys/fs/cgroup/service/memory.max", "1073741824\n");
    write_file(root, "sys/fs/cgroup/memory.max", "8589934592\n");

    assert_int_equal(cgroup_limit(root), 1073741824ULL);
}

void test_cgroup_v2_outside_mount(void **state) {
    char *root = *state;

    // A cgroup outside the mounted subtree cannot be read
    write_file(root, "proc_self_cgroup", "0::/docker/abcdef\n");
    write_file(root, "proc_self_mountinfo",
               "35 24 0:30 /docker/abc /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n");
    write_file(root, "sys/fs/cgroup/memory.max", "8589934592\n");

    assert_int_equal(cgroup_limit(root), 0);
}

void test_cgroup_v1_hybrid(void **state) {
    char *root = *state;

    // On hybrid systems, the memory controller is in cgroup v1, here mounted with the container's subtree
    write_file(root, "proc_self_cgroup", "12:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n0::/docker/abc\n");
    write_file(root, "proc_self_mountinfo",
               MOUNT_V1_CPU
               "40 30 0:35 /docker/abc /sys/fs/cgroup/memory rw,nosuid shared:20 - cgroup cgroup rw,memory\n"
               MOUNT_V2_UNIFIED);
    write_file(root, "sys/fs/cgroup/memory/memory.limit_in_bytes", "268435456\n");
    write_file(root, "sys/fs/cgroup/unified/memory.max", "8589934592\n");

    assert_int_equal(cgroup_limit(root), 268435456ULL);
}

void test_cgroup_v1_combined_controllers(void **state) {
    char *root = *state;

    // The memory controller is mounted together with cpu, without a "memory" directory
    write_file(root, "proc_self_cgroup", "5:cpu,memory:/\n");
    write_file(root, "proc_self_mountinfo",
               "41 30 0:36 / /sys/fs/cgroup/cpu,memory rw,nosuid shared:21 - cgroup cgroup rw,cpu,memory\n");
    write_file(root, "sys/fs/cgroup/cpu,memory/memory.limit_in_bytes", "1073741824\n");

    assert_int_equal(cgroup_limit(root), 1073741824ULL);
}

void test_cgroup_v1_unlimited(void **state) {
    char *root = *state;

    // cgroup v1 reports no limit as a huge value; w_get_memory_size() keeps the physical memory instead
    write_file(root, "proc_self_cgroup", "4:memory:/\n");
    write_file(root, "proc_self_mountinfo",
               "40 30 0:35 / /sys/fs/cgroup/memory rw,nosuid shared:20 - cgroup cgroup rw,memory\n");
    write_file(root, "sys/fs/cgroup/memory/memory.limit_in_bytes", "9223372036854771712\n");

    assert_int_equal(cgroup_limit(root), 9223372036854771712ULL);
}

void test_cgroup_escaped_mount_point(void **state) {
    char *root = *state;

    // mountinfo escapes spaces as \040
    write_file(root, "proc_self_cgroup", "0::/\n");
    write_file(root, "proc_self_mountinfo",
               "35 24 0:30 / /sys/fs/cgroup\\040v2 rw,nosuid shared:9 - cgroup2 cgroup2 rw\n");
    write_file(root, "sys/fs/cgroup v2/memory.max", "536870912\n");

    assert_int_equal(cgroup_limit(root), 536870912ULL);
}

void test_cgroup_no_mount(void **state) {
    char *root = *state;

    write_file(root, "proc_self_cgroup", "0::/\n");
    write_file(root, "proc_self_mountinfo", "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n");

    assert_int_equal(cgroup_limit(root), 0);
}

void test_cgroup_invalid_limit(void **state) {
    char *root = *state;

    write_file(root, "proc_self_cgroup", "0::/\n");
    write_file(root, "proc_self_mountinfo", MOUNT_V2);
    write_file(root, "sys/fs/cgroup/memory.max", "2G\n");

    assert_int_equal(cgroup_limit(root), 0);
}

void test_cgroup_no_proc_file(void **state) {
    char *root = *state;

    assert_int_equal(cgroup_limit(root), 0);
}

void test_w_cgroup_has_controller(void **state) {
    assert_true(w_cgroup_has_controller("memory", "memory"));
    assert_true(w_cgroup_has_controller("cpu,memory", "memory"));
    assert_true(w_cgroup_has_controller("memory,pids", "memory"));
    assert_false(w_cgroup_has_controller("memoryx", "memory"));
    assert_false(w_cgroup_has_controller("cpu,cpuacct", "memory"));
    assert_false(w_cgroup_has_controller("", "memory"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_get_physical_memory),
        cmocka_unit_test(test_w_get_memory_size),
        cmocka_unit_test_setup_teardown(test_cgroup_v2_own_limit, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v2_ancestor_limit, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v2_no_limit, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v2_container_root, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v2_mounted_subtree, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v2_outside_mount, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v1_hybrid, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v1_combined_controllers, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_v1_unlimited, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_escaped_mount_point, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_no_mount, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_invalid_limit, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test_setup_teardown(test_cgroup_no_proc_file, setup_cgroup_root, teardown_cgroup_root),
        cmocka_unit_test(test_w_cgroup_has_controller),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
