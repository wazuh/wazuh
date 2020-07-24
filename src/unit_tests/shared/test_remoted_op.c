#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "shared.h"
#include "remoted_op.h"

/* wraps */

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

/* setup/teardown */

int setup_remoted_op(void **state) {
    return 0;
}

int teardown_remoted_op(void **state) {
    return 0;
}

/* tests */

/* Tests get_os_arch */

#ifndef CLIENT

void test_get_os_arch_x86_64(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |x86_64";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |x86_64: x86_64");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("x86_64", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_i386(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |i386";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |i386: i386");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("i386", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_i686(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |i686";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |i686: i686");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("i686", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_sparc(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |sparc";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |sparc: sparc");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("sparc", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_amd64(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |amd64";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |amd64: amd64");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("amd64", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_ia64(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-ia64 |#1 SMP Debian |ia64";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-ia64 |#1 SMP Debian |ia64: ia64");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("ia64", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_AIX(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-AIX |#1 SMP Debian |AIX";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-AIX |#1 SMP Debian |AIX: AIX");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("AIX", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_armv6(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-armv6 |#1 SMP Debian |armv6";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-armv6 |#1 SMP Debian |armv6: armv6");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("armv6", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_armv7(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-armv7 |#1 SMP Debian |armv7";

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-armv7 |#1 SMP Debian |armv7: armv7");

    char* os_arch = get_os_arch(uname);

    assert_string_equal("armv7", os_arch);

    os_free(os_arch);
}

/* Tests parse_agent_update_msg */

void test_parse_agent_update_msg_ok_debian(void **state)
{
    char *msg = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64 \
[Debian GNU/Linux|debian: 10 (buster)] - Wazuh v3.13.0 / ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 \
merged.mg\n#\"_agent_ip\":192.168.0.143\n";

    char *version = NULL;
    char *os_name = NULL;
    char *os_major = NULL;
    char *os_minor = NULL;
    char *os_build = NULL;
    char *os_version = NULL;
    char *os_codename = NULL;
    char *os_platform = NULL;
    char *os_arch = NULL;
    char *uname = NULL;
    char *config_sum = NULL;
    char *merged_sum = NULL;
    char *agent_ip = NULL;

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64: x86_64");

    int result = parse_agent_update_msg (msg, &version, &os_name, &os_major, &os_minor, &os_build, &os_version,
                                         &os_codename, &os_platform, &os_arch, &uname, &config_sum, &merged_sum, &agent_ip);
    
    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.0",version);
    assert_string_equal("Debian GNU/Linux",os_name);
    assert_string_equal("10",os_major);
    assert_null(os_minor);
    assert_null(os_build);
    assert_string_equal("10",os_version);
    assert_string_equal("buster",os_codename);
    assert_string_equal("debian",os_platform);
    assert_string_equal("x86_64",os_arch);
    assert_string_equal("Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64",uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00",config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251",merged_sum);
    assert_string_equal("192.168.0.143",agent_ip);

    os_free(version);
    os_free(os_name);
    os_free(os_major);
    os_free(os_minor);
    os_free(os_build);
    os_free(os_version);
    os_free(os_codename);
    os_free(os_platform);
    os_free(os_arch);
    os_free(uname);
    os_free(config_sum);
    os_free(merged_sum);
    os_free(agent_ip);
}

void test_parse_agent_update_msg_ok_ubuntu(void **state)
{
    char *msg = "Linux |ubuntu2004 |5.4.0-42-generic |#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 |x86_64 \
[Ubuntu|ubuntu: 20.04 LTS (Focal Fossa)] - Wazuh v3.13.1 / ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 \
merged.mg\n#\"_agent_ip\":192.168.0.133\n";

    char *version = NULL;
    char *os_name = NULL;
    char *os_major = NULL;
    char *os_minor = NULL;
    char *os_build = NULL;
    char *os_version = NULL;
    char *os_codename = NULL;
    char *os_platform = NULL;
    char *os_arch = NULL;
    char *uname = NULL;
    char *config_sum = NULL;
    char *merged_sum = NULL;
    char *agent_ip = NULL;

    expect_string(__wrap__mdebug2, formatted_msg, "Detected architecture from Linux |ubuntu2004 |5.4.0-42-generic |#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 |x86_64: x86_64");

    int result = parse_agent_update_msg (msg, &version, &os_name, &os_major, &os_minor, &os_build, &os_version,
                                         &os_codename, &os_platform, &os_arch, &uname, &config_sum, &merged_sum, &agent_ip);
    
    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.1", version);
    assert_string_equal("Ubuntu", os_name);
    assert_string_equal("20", os_major);
    assert_string_equal("04", os_minor);
    assert_null(os_build);
    assert_string_equal("20.04 LTS", os_version);
    assert_string_equal("Focal Fossa", os_codename);
    assert_string_equal("ubuntu", os_platform);
    assert_string_equal("x86_64", os_arch);
    assert_string_equal("Linux |ubuntu2004 |5.4.0-42-generic |#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 |x86_64", uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00",config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251",merged_sum);
    assert_string_equal("192.168.0.133",agent_ip);

    os_free(version);
    os_free(os_name);
    os_free(os_major);
    os_free(os_minor);
    os_free(os_build);
    os_free(os_version);
    os_free(os_codename);
    os_free(os_platform);
    os_free(os_arch);
    os_free(uname);
    os_free(config_sum);
    os_free(merged_sum);
    os_free(agent_ip);
}

void test_parse_agent_update_msg_ok_windows(void **state)
{
    char *msg = "Microsoft Windows 10 Enterprise [Ver: 10.0.14393] - Wazuh v3.13.1 \
/ ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 \
merged.mg\n#\"_agent_ip\":192.168.0.164\n";

    char *version = NULL;
    char *os_name = NULL;
    char *os_major = NULL;
    char *os_minor = NULL;
    char *os_build = NULL;
    char *os_version = NULL;
    char *os_codename = NULL;
    char *os_platform = NULL;
    char *os_arch = NULL;
    char *uname = NULL;
    char *config_sum = NULL;
    char *merged_sum = NULL;
    char *agent_ip = NULL;

    int result = parse_agent_update_msg (msg, &version, &os_name, &os_major, &os_minor, &os_build, &os_version,
                                         &os_codename, &os_platform, &os_arch, &uname, &config_sum, &merged_sum, &agent_ip);
    
    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.1", version);
    assert_string_equal("Microsoft Windows 10 Enterprise", os_name);
    assert_string_equal("10", os_major);
    assert_string_equal("0", os_minor);
    assert_string_equal("14393", os_build);
    assert_string_equal("10.0.14393", os_version);
    assert_null(os_codename);
    assert_string_equal("windows", os_platform);
    assert_null(os_arch);
    assert_string_equal("Microsoft Windows 10 Enterprise", uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00",config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251",merged_sum);
    assert_string_equal("192.168.0.164",agent_ip);

    os_free(version);
    os_free(os_name);
    os_free(os_major);
    os_free(os_minor);
    os_free(os_build);
    os_free(os_version);
    os_free(os_codename);
    os_free(os_platform);
    os_free(os_arch);
    os_free(uname);
    os_free(config_sum);
    os_free(merged_sum);
    os_free(agent_ip);
}

#endif

int main()
{
    const struct CMUnitTest tests[] = 
    {
#ifndef CLIENT
        // Tests get_os_arch
        cmocka_unit_test_setup_teardown(test_get_os_arch_x86_64, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_i386, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_i686, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_sparc, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_amd64, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_ia64, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_AIX, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_armv6, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_get_os_arch_armv7, setup_remoted_op, teardown_remoted_op),
        // Tests parse_agent_update_msg
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_debian, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_ubuntu, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_windows, setup_remoted_op, teardown_remoted_op)
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}
