#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#include "shared.h"
#include "remoted_op.h"

/* setup/teardown */

int setup_remoted_op(void **state) {
    return 0;
}

int teardown_remoted_op(void **state) {
    return 0;
}

/* tests */

/* Tests get_os_arch */

void test_get_os_arch_x86_64(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |x86_64";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("x86_64", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_i386(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |i386";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("i386", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_i686(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |i686";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("i686", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_sparc(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |sparc";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("sparc", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_amd64(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian |amd64";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("amd64", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_ia64(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-ia64 |#1 SMP Debian |ia64";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("ia64", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_AIX(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-AIX |#1 SMP Debian |AIX";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("AIX", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_armv6(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-armv6 |#1 SMP Debian |armv6";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("armv6", os_arch);

    os_free(os_arch);
}

void test_get_os_arch_armv7(void **state)
{
    char* uname = "Linux |debian10 |4.19.0-9-armv7 |#1 SMP Debian |armv7";

    char* os_arch = get_os_arch(uname);

    assert_string_equal("armv7", os_arch);

    os_free(os_arch);
}

// Tests parse_uname_string

void test_parse_uname_string_windows1(void **state)
{
    char *uname = NULL;
    os_strdup("Microsoft Windows 10 Enterprise [Ver: 10.0.14393]", uname);

    os_data *osd = NULL;
    os_calloc(1, sizeof(os_data), osd);

    parse_uname_string(uname, osd);

    assert_string_equal("Microsoft Windows 10 Enterprise", osd->os_name);
    assert_string_equal("10", osd->os_major);
    assert_string_equal("0", osd->os_minor);
    assert_string_equal("14393", osd->os_build);
    assert_string_equal("10.0.14393", osd->os_version);
    assert_null(osd->os_codename);
    assert_string_equal("windows", osd->os_platform);
    assert_null(osd->os_arch);
    assert_string_equal("Microsoft Windows 10 Enterprise", uname);

    os_free(osd->os_name);
    os_free(osd->os_major);
    os_free(osd->os_minor);
    os_free(osd->os_build);
    os_free(osd->os_version);
    os_free(osd->os_codename);
    os_free(osd->os_platform);
    os_free(osd->os_arch);
    os_free(osd);
    os_free(uname);
}

void test_parse_uname_string_windows2(void **state)
{
    char *uname = NULL;
    os_strdup("Microsoft Windows Server 2019 Datacenter Evaluation [Ver: 10.0.17763.1935]", uname);

    os_data *osd = NULL;
    os_calloc(1, sizeof(os_data), osd);

    parse_uname_string(uname, osd);

    assert_string_equal("Microsoft Windows Server 2019 Datacenter Evaluation", osd->os_name);
    assert_string_equal("10", osd->os_major);
    assert_string_equal("0", osd->os_minor);
    assert_string_equal("17763.1935", osd->os_build);
    assert_string_equal("10.0.17763.1935", osd->os_version);
    assert_null(osd->os_codename);
    assert_string_equal("windows", osd->os_platform);
    assert_null(osd->os_arch);
    assert_string_equal("Microsoft Windows Server 2019 Datacenter Evaluation", uname);

    os_free(osd->os_name);
    os_free(osd->os_major);
    os_free(osd->os_minor);
    os_free(osd->os_build);
    os_free(osd->os_version);
    os_free(osd->os_codename);
    os_free(osd->os_platform);
    os_free(osd->os_arch);
    os_free(osd);
    os_free(uname);
}

void test_parse_uname_string_linux(void **state)
{
    char *uname = NULL;
    os_strdup("Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64 \
[Debian GNU/Linux|debian: 10 (buster)]", uname);

    os_data *osd = NULL;
    os_calloc(1, sizeof(os_data), osd);

    parse_uname_string(uname, osd);

    assert_string_equal("Debian GNU/Linux", osd->os_name);
    assert_string_equal("10", osd->os_major);
    assert_null(osd->os_minor);
    assert_null(osd->os_build);
    assert_string_equal("10", osd->os_version);
    assert_string_equal("buster", osd->os_codename);
    assert_string_equal("debian", osd->os_platform);
    assert_string_equal("x86_64", osd->os_arch);
    assert_string_equal("debian10", osd->hostname);
    assert_string_equal("Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64",uname);

    os_free(osd->os_name);
    os_free(osd->os_major);
    os_free(osd->os_minor);
    os_free(osd->os_build);
    os_free(osd->os_version);
    os_free(osd->os_codename);
    os_free(osd->os_platform);
    os_free(osd->os_arch);
    os_free(osd->hostname);
    os_free(osd);
    os_free(uname);
}

void test_parse_uname_string_macos(void **state)
{
    char *uname = NULL;
    os_strdup("Darwin |TESTmac.local |19.6.0 |Darwin Kernel Version 19.6.0: Thu Jun 18 20:49:00 PDT 2020; \
root:xnu-6153.141.1~1/RELEASE_X86_64 |x86_64 [Mac OS X|darwin: 10.15.6 (Catalina)]", uname);

    os_data *osd = NULL;
    os_calloc(1, sizeof(os_data), osd);

    parse_uname_string(uname, osd);

    assert_string_equal("Mac OS X", osd->os_name);
    assert_string_equal("10", osd->os_major);
    assert_string_equal("15", osd->os_minor);
    assert_null(osd->os_build);
    assert_string_equal("10.15.6", osd->os_version);
    assert_string_equal("Catalina", osd->os_codename);
    assert_string_equal("darwin", osd->os_platform);
    assert_string_equal("x86_64", osd->os_arch);
    assert_string_equal("TESTmac.local", osd->hostname);
    assert_string_equal("Darwin |TESTmac.local |19.6.0 |Darwin Kernel Version 19.6.0: Thu Jun 18 20:49:00 PDT 2020; root:xnu-6153.141.1~1/RELEASE_X86_64 |x86_64",uname);

    os_free(osd->os_name);
    os_free(osd->os_major);
    os_free(osd->os_minor);
    os_free(osd->os_build);
    os_free(osd->os_version);
    os_free(osd->os_codename);
    os_free(osd->os_platform);
    os_free(osd->os_arch);
    os_free(osd->hostname);
    os_free(osd);
    os_free(uname);
}

/* Tests parse_agent_update_msg */

void test_parse_agent_update_msg_missing_uname(void **state)
{
    char *msg = "No system info available - Wazuh v3.13.2 / ab73af41699f13fdd81903b5f23d8d00\n\
fd756ba04d9c32c8848d4608bec41251 merged.mg\n#\"_agent_ip\":192.168.0.133\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.2", agent_data->version);
    assert_null(agent_data->osd->os_name);
    assert_null(agent_data->osd->os_major);
    assert_null(agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_null(agent_data->osd->os_version);
    assert_null(agent_data->osd->os_codename);
    assert_null(agent_data->osd->os_platform);
    assert_null(agent_data->osd->os_arch);
    assert_string_equal("No system info available", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.133", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_missing_config_sum(void **state)
{
    char *msg = "Linux |ubuntu2204 |5.15.0-58-generic |#64-Ubuntu SMP Thu Jan 5 11:43:13 UTC 2023 |x86_64 [Ubuntu|ubuntu: 22.04 LTS (Jammy Jellyfish)] - Wazuh v3.13.2\n\
fd756ba04d9c32c8848d4608bec41251 merged.mg\n#\"_agent_ip\":192.168.0.133\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.2", agent_data->version);
    assert_string_equal("Ubuntu", agent_data->osd->os_name);
    assert_string_equal("22", agent_data->osd->os_major);
    assert_string_equal("04", agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("22.04 LTS", agent_data->osd->os_version);
    assert_string_equal("Jammy Jellyfish", agent_data->osd->os_codename);
    assert_string_equal("ubuntu", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Linux |ubuntu2204 |5.15.0-58-generic |#64-Ubuntu SMP Thu Jan 5 11:43:13 UTC 2023 |x86_64", agent_data->osd->os_uname);
    assert_null(agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.133", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_missing_merged_sum(void **state)
{
    char *msg = "Linux |ubuntu2204 |5.15.0-58-generic |#64-Ubuntu SMP Thu Jan 5 11:43:13 UTC 2023 |x86_64 [Ubuntu|ubuntu: 22.04 LTS (Jammy Jellyfish)] - Wazuh v3.13.2\
 / ab73af41699f13fdd81903b5f23d8d00\nx merged.mg\n#\"_agent_ip\":192.168.0.133\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.2", agent_data->version);
    assert_string_equal("Ubuntu", agent_data->osd->os_name);
    assert_string_equal("22", agent_data->osd->os_major);
    assert_string_equal("04", agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("22.04 LTS", agent_data->osd->os_version);
    assert_string_equal("Jammy Jellyfish", agent_data->osd->os_codename);
    assert_string_equal("ubuntu", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Linux |ubuntu2204 |5.15.0-58-generic |#64-Ubuntu SMP Thu Jan 5 11:43:13 UTC 2023 |x86_64", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("x", agent_data->merged_sum);
    assert_string_equal("192.168.0.133", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_ok_debian(void **state)
{
    char *msg = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64 \
[Debian GNU/Linux|debian: 10 (buster)] - Wazuh v3.13.0 / ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 \
merged.mg\n#\"_agent_ip\":192.168.0.143\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.0", agent_data->version);
    assert_string_equal("Debian GNU/Linux", agent_data->osd->os_name);
    assert_string_equal("10", agent_data->osd->os_major);
    assert_null(agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("10", agent_data->osd->os_version);
    assert_string_equal("buster", agent_data->osd->os_codename);
    assert_string_equal("debian", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.143", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_ok_ubuntu(void **state)
{
    char *msg = "Linux |ubuntu2004 |5.4.0-42-generic |#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 |x86_64 \
[Ubuntu|ubuntu: 20.04 LTS (Focal Fossa)] - Wazuh v3.13.1 / ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 \
merged.mg\n#\"_agent_ip\":192.168.0.133\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.1", agent_data->version);
    assert_string_equal("Ubuntu", agent_data->osd->os_name);
    assert_string_equal("20", agent_data->osd->os_major);
    assert_string_equal("04", agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("20.04 LTS", agent_data->osd->os_version);
    assert_string_equal("Focal Fossa", agent_data->osd->os_codename);
    assert_string_equal("ubuntu", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Linux |ubuntu2004 |5.4.0-42-generic |#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 |x86_64", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.133", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_ok_archlinux(void **state)
{
    char *msg = "Linux |archlinux |5.15.2-arch1-1 |#1 SMP PREEMPT Fri, 12 Nov 2021 19:22:10 +0000 |x86_64 \
[Arch Linux|arch: ] - Wazuh v4.3.0 / ab73af41699f13fdd81903b5f23d8d00\n4a8724b20dee0124ff9656783c490c4e \
merged.mg\n#\"_agent_ip\":192.168.33.18\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v4.3.0", agent_data->version);
    assert_string_equal("Arch Linux", agent_data->osd->os_name);
    assert_null(agent_data->osd->os_major);
    assert_null(agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("", agent_data->osd->os_version);
    assert_null(agent_data->osd->os_codename);
    assert_string_equal("arch", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Linux |archlinux |5.15.2-arch1-1 |#1 SMP PREEMPT Fri, 12 Nov 2021 19:22:10 +0000 |x86_64", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("4a8724b20dee0124ff9656783c490c4e", agent_data->merged_sum);
    assert_string_equal("192.168.33.18", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_ok_macos(void **state)
{
    char *msg = "Darwin |TESTmac.local |19.6.0 |Darwin Kernel Version 19.6.0: Thu Jun 18 20:49:00 PDT 2020; \
root:xnu-6153.141.1~1/RELEASE_X86_64 |x86_64 [Mac OS X|darwin: 10.15.6 (Catalina)] - Wazuh v3.13.1 / \
ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 merged.mg\n#\"_agent_ip\":192.168.0.123\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.1", agent_data->version);
    assert_string_equal("Mac OS X", agent_data->osd->os_name);
    assert_string_equal("10", agent_data->osd->os_major);
    assert_string_equal("15", agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("10.15.6", agent_data->osd->os_version);
    assert_string_equal("Catalina", agent_data->osd->os_codename);
    assert_string_equal("darwin", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Darwin |TESTmac.local |19.6.0 |Darwin Kernel Version 19.6.0: Thu Jun 18 20:49:00 PDT 2020; root:xnu-6153.141.1~1/RELEASE_X86_64 |x86_64", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.123", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_ok_windows(void **state)
{
    char *msg = "Microsoft Windows 10 Enterprise [Ver: 10.0.14393] - Wazuh v3.13.1 \
/ ab73af41699f13fdd81903b5f23d8d00\nfd756ba04d9c32c8848d4608bec41251 \
merged.mg\n#\"_agent_ip\":192.168.0.164\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.1", agent_data->version);
    assert_string_equal("Microsoft Windows 10 Enterprise", agent_data->osd->os_name);
    assert_string_equal("10", agent_data->osd->os_major);
    assert_string_equal("0", agent_data->osd->os_minor);
    assert_string_equal("14393", agent_data->osd->os_build);
    assert_string_equal("10.0.14393", agent_data->osd->os_version);
    assert_null(agent_data->osd->os_codename);
    assert_string_equal("windows", agent_data->osd->os_platform);
    assert_null(agent_data->osd->os_arch);
    assert_string_equal("Microsoft Windows 10 Enterprise", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.164", agent_data->agent_ip);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_agent_update_msg_ok_labels(void **state)
{
    char *msg = "Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64 \
[Debian GNU/Linux|debian: 10 (buster)] - Wazuh v3.13.0 / ab73af41699f13fdd81903b5f23d8d00\
\n\"key1\":value1\n\"key2\":value2\n!\"hkey1\":hvalue1\n!\"hkey2\":hvalue2\
\nfd756ba04d9c32c8848d4608bec41251 merged.mg\n#\"_agent_ip\":192.168.0.143\n";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_agent_update_msg(msg, agent_data);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("Wazuh v3.13.0", agent_data->version);
    assert_string_equal("Debian GNU/Linux", agent_data->osd->os_name);
    assert_string_equal("10", agent_data->osd->os_major);
    assert_null(agent_data->osd->os_minor);
    assert_null(agent_data->osd->os_build);
    assert_string_equal("10", agent_data->osd->os_version);
    assert_string_equal("buster", agent_data->osd->os_codename);
    assert_string_equal("debian", agent_data->osd->os_platform);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("Linux |debian10 |4.19.0-9-amd64 |#1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) |x86_64", agent_data->osd->os_uname);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.0.143", agent_data->agent_ip);
    assert_string_equal("\"key1\":value1\n\"key2\":value2\n!\"hkey1\":hvalue1\n!\"hkey2\":hvalue2", agent_data->labels);

    wdb_free_agent_info_data(agent_data);
}

/* Tests parse_json_keepalive */

void test_parse_json_keepalive_invalid_json(void **state)
{
    char* json = "not a json";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_json_keepalive(json, agent_data, NULL, NULL, NULL, NULL);

    assert_int_equal(OS_INVALID, result);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_missing_agent(void **state)
{
    char* json = "{\"version\":\"1.0\",\"host\":{}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_json_keepalive(json, agent_data, NULL, NULL, NULL, NULL);

    assert_int_equal(OS_INVALID, result);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_linux_complete(void **state)
{
    char* json = "{\"version\":\"1.0\",\"agent\":{\"id\":\"001\",\"name\":\"agent1\",\"version\":\"v5.0.0\",\
\"config_sum\":\"ab73af41699f13fdd81903b5f23d8d00\",\"merged_sum\":\"fd756ba04d9c32c8848d4608bec41251\",\
\"ip\":\"192.168.1.100\",\
\"uname\":\"Linux |ubuntu-test |5.4.0-42-generic |#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 |x86_64 [Ubuntu 20.04|ubuntu: 20.04 (focal)]\",\
\"labels\":\"key1:value1\\nkey2:value2\"},\
\"host\":{\"hostname\":\"ubuntu-test\",\"architecture\":\"x86_64\",\
\"os\":{\"name\":\"Ubuntu\",\"version\":\"20.04\",\"platform\":\"ubuntu\",\"type\":\"linux\"}}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_json_keepalive(json, agent_data, NULL, NULL, NULL, NULL);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("v5.0.0", agent_data->version);
    assert_string_equal("ab73af41699f13fdd81903b5f23d8d00", agent_data->config_sum);
    assert_string_equal("fd756ba04d9c32c8848d4608bec41251", agent_data->merged_sum);
    assert_string_equal("192.168.1.100", agent_data->agent_ip);
    assert_string_equal("key1:value1\nkey2:value2", agent_data->labels);
    assert_string_equal("Ubuntu", agent_data->osd->os_name);
    assert_string_equal("20.04", agent_data->osd->os_version);
    assert_string_equal("ubuntu", agent_data->osd->os_platform);
    assert_string_equal("linux", agent_data->osd->os_type);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("ubuntu-test", agent_data->osd->hostname);
    assert_string_equal("20", agent_data->osd->os_major);
    assert_string_equal("04", agent_data->osd->os_minor);
    assert_string_equal("focal", agent_data->osd->os_codename);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_windows(void **state)
{
    char* json = "{\"version\":\"1.0\",\"agent\":{\"version\":\"v5.0.0\",\"config_sum\":\"abc123\",\
\"merged_sum\":\"def456\",\"uname\":\"Microsoft Windows Server 2019 Datacenter [Ver: 10.0.17763.1879]\"},\
\"host\":{\"hostname\":\"win-server\",\"architecture\":\"x86_64\",\
\"os\":{\"name\":\"Microsoft Windows Server 2019\",\"version\":\"10.0.17763\",\"platform\":\"windows\",\
\"type\":\"windows\"}}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_json_keepalive(json, agent_data, NULL, NULL, NULL, NULL);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("v5.0.0", agent_data->version);
    assert_string_equal("abc123", agent_data->config_sum);
    assert_string_equal("def456", agent_data->merged_sum);
    assert_string_equal("Microsoft Windows Server 2019", agent_data->osd->os_name);
    assert_string_equal("10.0.17763", agent_data->osd->os_version);
    assert_string_equal("windows", agent_data->osd->os_platform);
    assert_string_equal("windows", agent_data->osd->os_type);
    assert_string_equal("x86_64", agent_data->osd->os_arch);
    assert_string_equal("win-server", agent_data->osd->hostname);
    assert_string_equal("10", agent_data->osd->os_major);
    assert_string_equal("0", agent_data->osd->os_minor);
    assert_string_equal("17763.1879", agent_data->osd->os_build);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_minimal(void **state)
{
    char* json = "{\"version\":\"1.0\",\"agent\":{\"version\":\"v5.0.0\"}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    int result = parse_json_keepalive(json, agent_data, NULL, NULL, NULL, NULL);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("v5.0.0", agent_data->version);
    assert_null(agent_data->config_sum);
    assert_null(agent_data->merged_sum);
    assert_null(agent_data->agent_ip);
    assert_null(agent_data->labels);
    assert_non_null(agent_data->osd);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_with_groups(void **state)
{
    char* json = "{\"version\":\"1.0\",\"agent\":{\"version\":\"v5.0.0\",\"groups\":[\"group1\",\"group2\",\"group3\"]}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    char **groups = NULL;
    size_t groups_count = 0;

    int result = parse_json_keepalive(json, agent_data, &groups, &groups_count, NULL, NULL);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("v5.0.0", agent_data->version);

    // Check groups were parsed
    assert_non_null(groups);
    assert_int_equal(3, groups_count);
    assert_string_equal("group1", groups[0]);
    assert_string_equal("group2", groups[1]);
    assert_string_equal("group3", groups[2]);

    // Free groups
    for (size_t i = 0; i < groups_count; i++) {
        os_free(groups[i]);
    }
    os_free(groups);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_empty_groups(void **state)
{
    char* json = "{\"version\":\"1.0\",\"agent\":{\"version\":\"v5.0.0\",\"groups\":[]}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    char **groups = NULL;
    size_t groups_count = 0;

    int result = parse_json_keepalive(json, agent_data, &groups, &groups_count, NULL, NULL);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("v5.0.0", agent_data->version);

    // Empty array should result in NULL groups
    assert_null(groups);
    assert_int_equal(0, groups_count);

    wdb_free_agent_info_data(agent_data);
}

void test_parse_json_keepalive_no_groups(void **state)
{
    char* json = "{\"version\":\"1.0\",\"agent\":{\"version\":\"v5.0.0\"}}";

    agent_info_data *agent_data = NULL;
    os_calloc(1, sizeof(agent_info_data), agent_data);

    char **groups = NULL;
    size_t groups_count = 0;

    int result = parse_json_keepalive(json, agent_data, &groups, &groups_count, NULL, NULL);

    assert_int_equal(OS_SUCCESS, result);
    assert_string_equal("v5.0.0", agent_data->version);

    // No groups field should result in NULL groups
    assert_null(groups);
    assert_int_equal(0, groups_count);

    wdb_free_agent_info_data(agent_data);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
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
        // Tests parse_uname_string
        cmocka_unit_test_setup_teardown(test_parse_uname_string_windows1, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_uname_string_windows2, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_uname_string_linux, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_uname_string_macos, setup_remoted_op, teardown_remoted_op),
        // Tests parse_agent_update_msg
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_missing_uname, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_debian, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_ubuntu, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_archlinux, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_macos, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_windows, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_agent_update_msg_ok_labels, setup_remoted_op, teardown_remoted_op),
        // Tests parse_json_keepalive
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_invalid_json, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_missing_agent, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_linux_complete, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_windows, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_minimal, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_with_groups, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_empty_groups, setup_remoted_op, teardown_remoted_op),
        cmocka_unit_test_setup_teardown(test_parse_json_keepalive_no_groups, setup_remoted_op, teardown_remoted_op)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}
