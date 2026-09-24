/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "shared.h"
#include "rootcheck.h"

rkconfig rootcheck;

typedef struct {
    const char *name;
    short flags;
} fake_if_t;

/* Interfaces reported by the wrapped ioctl() */
static const fake_if_t *fake_ifs;
static int fake_ifs_count;
static int ifconf_ret;

int __wrap_socket(__attribute__((unused)) int domain,
                  __attribute__((unused)) int type,
                  __attribute__((unused)) int protocol)
{
    return mock_type(int);
}

/* Keep the mocked descriptor from reaching the real close() */
int __wrap_close(__attribute__((unused)) int fd)
{
    return 0;
}

/*
 * SIOCGIFCONF returns the names in fake_ifs. SIOCGIFFLAGS returns the flags of
 * the matching entry, or fails (as the kernel does) for unused ifreq slots.
 */
int __wrap_ioctl(__attribute__((unused)) int fd, unsigned long request, ...)
{
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);

    if (request == SIOCGIFCONF) {
        struct ifconf *ifc = arg;
        struct ifreq *ifr = (struct ifreq *)ifc->ifc_buf;

        if (ifconf_ret < 0) {
            return ifconf_ret;
        }

        for (int i = 0; i < fake_ifs_count; i++) {
            strncpy(ifr[i].ifr_name, fake_ifs[i].name, IFNAMSIZ - 1);
        }
        ifc->ifc_len = fake_ifs_count * sizeof(struct ifreq);
        return 0;
    }

    if (request == SIOCGIFFLAGS) {
        struct ifreq *ifr = arg;

        for (int i = 0; i < fake_ifs_count; i++) {
            if (ifr->ifr_name[0] != '\0' && strcmp(ifr->ifr_name, fake_ifs[i].name) == 0) {
                ifr->ifr_flags = fake_ifs[i].flags;
                return 0;
            }
        }
        errno = ENODEV;
        return -1;
    }

    fail_msg("Unexpected ioctl request %lu", request);
    return -1;
}

/* The fix must never hand the interface name to a shell */
int __wrap_system(const char *command)
{
    fail_msg("check_rc_if() invoked a shell: system(\"%s\")", command);
    return -1;
}

int __wrap_notify_rk(int rk_type, const char *msg)
{
    check_expected(rk_type);
    check_expected(msg);
    return mock_type(int);
}

void __wrap__mterror(const char *tag,
                     __attribute__((unused)) const char *file,
                     __attribute__((unused)) int line,
                     __attribute__((unused)) const char *func,
                     const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

static void expect_notify_rk(int rk_type, const char *msg)
{
    expect_value(__wrap_notify_rk, rk_type, rk_type);
    expect_string(__wrap_notify_rk, msg, msg);
    will_return(__wrap_notify_rk, 0);
}

static void set_fake_ifs(const fake_if_t *ifs, int count)
{
    fake_ifs = ifs;
    fake_ifs_count = count;
}

static int setup(void **state)
{
    (void)state;
    memset(&rootcheck, 0, sizeof(rkconfig));
    set_fake_ifs(NULL, 0);
    ifconf_ret = 0;
    return 0;
}

/* ===================================================================
 * Tests
 *
 * __wrap_system() aborts the test, so any shell invocation from
 * check_rc_if() is a hard failure.
 * =================================================================== */

static void test_no_promisc_alert_ok(void **state)
{
    (void)state;
    static const fake_if_t ifs[] = {
        {"lo", IFF_UP | IFF_LOOPBACK},
        {"eth0", IFF_UP | IFF_BROADCAST},
    };
    set_fake_ifs(ifs, 2);

    will_return(__wrap_socket, 3);
    expect_notify_rk(ALERT_OK, "No problem detected on ifconfig/ifs. Analyzed 2 interfaces.");

    check_rc_if();
}

static void test_promisc_alert(void **state)
{
    (void)state;
    static const fake_if_t ifs[] = {
        {"lo", IFF_UP | IFF_LOOPBACK},
        {"eth0", IFF_UP | IFF_BROADCAST | IFF_PROMISC},
    };
    set_fake_ifs(ifs, 2);

    will_return(__wrap_socket, 3);
    expect_notify_rk(ALERT_SYSTEM_CRIT, "Interface 'eth0' in promiscuous mode.");

    check_rc_if();
}

static void test_promisc_shell_metachar_name_not_executed(void **state)
{
    (void)state;
    static const fake_if_t ifs[] = {
        {"x;id>poc;#", IFF_UP | IFF_PROMISC},
        {"$(id)", IFF_UP | IFF_PROMISC},
    };
    set_fake_ifs(ifs, 2);

    will_return(__wrap_socket, 3);
    expect_notify_rk(ALERT_SYSTEM_CRIT, "Interface 'x;id>poc;#' in promiscuous mode.");
    expect_notify_rk(ALERT_SYSTEM_CRIT, "Interface '$(id)' in promiscuous mode.");

    check_rc_if();
}

static void test_socket_fail(void **state)
{
    (void)state;

    will_return(__wrap_socket, -1);
    expect_string(__wrap__mterror, tag, "rootcheck");
    expect_string(__wrap__mterror, formatted_msg, "Error checking interfaces (socket)");

    check_rc_if();
}

static void test_ifconf_fail(void **state)
{
    (void)state;
    ifconf_ret = -1;

    will_return(__wrap_socket, 3);
    expect_string(__wrap__mterror, tag, "rootcheck");
    expect_string(__wrap__mterror, formatted_msg, "Error checking interfaces (ioctl)");

    check_rc_if();
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_no_promisc_alert_ok, setup),
        cmocka_unit_test_setup(test_promisc_alert, setup),
        cmocka_unit_test_setup(test_promisc_shell_metachar_name_not_executed, setup),
        cmocka_unit_test_setup(test_socket_fail, setup),
        cmocka_unit_test_setup(test_ifconf_fail, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
