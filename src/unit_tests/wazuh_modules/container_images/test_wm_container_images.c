/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Tests for the container_images module configuration parser.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "shared.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wmodules.h"
#include "wm_container_images.h"
#include "../scheduling/wmodules_scheduling_helpers.h"

static void wmodule_cleanup(wmodule *module) {
    if (module) {
        wm_container_images_t *data = (wm_container_images_t *)module->data;

        if (data && data->references) {
            for (int i = 0; i < data->references_count; i++) {
                os_free(data->references[i].type);
                os_free(data->references[i].value);
            }
            os_free(data->references);
        }

        if (data && data->registries) {
            for (int i = 0; i < data->registries_count; i++) {
                os_free(data->registries[i].host);
                os_free(data->registries[i].user_key);
                os_free(data->registries[i].passkey_key);
            }
            os_free(data->registries);
        }

        if (data) {
            os_free(data->ca_bundle);
        }

        os_free(module->data);
        os_free(module->tag);
        os_free(module);
    }
}

static int setup_test_read(void **state) {
    test_structure *test = calloc(1, sizeof(test_structure));
    test->module = calloc(1, sizeof(wmodule));
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

void test_read_defaults(void **state) {
    const char *string = "";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->scan_on_start, 1);
    assert_int_equal(data->interval, WM_CONTAINER_IMAGES_DEFAULT_INTERVAL);
    assert_int_equal(data->references_count, 0);
}

void test_read_full_configuration(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<scan_on_start>no</scan_on_start>\n"
        "<interval>30m</interval>\n"
        "<references>\n"
        "  <archive>/var/tmp/images/myapp.tar</archive>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->scan_on_start, 0);
    assert_int_equal(data->interval, 1800);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->references[0].type, "archive");
    assert_string_equal(data->references[0].value, "/var/tmp/images/myapp.tar");
}

void test_read_multiple_archive_references(void **state) {
    const char *string =
        "<references>\n"
        "  <archive>/opt/a</archive>\n"
        "  <archive>/opt/b</archive>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->references_count, 2);
    assert_string_equal(data->references[0].value, "/opt/a");
    assert_string_equal(data->references[1].value, "/opt/b");
}

void test_read_every_reference_type_is_accepted(void **state) {
    // The grammar holds the three entry types, so implementing one later adds behaviour
    // without changing the configuration.
    const char *string =
        "<references>\n"
        "  <ref>nginx:1.27</ref>\n"
        "  <archive>/var/tmp/images/myapp.tar</archive>\n"
        "  <local>alpine:latest</local>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->references_count, 3);
    assert_string_equal(data->references[0].type, "ref");
    assert_string_equal(data->references[0].value, "nginx:1.27");
    assert_string_equal(data->references[1].type, "archive");
    assert_string_equal(data->references[2].type, "local");
    assert_string_equal(data->references[2].value, "alpine:latest");
}

void test_read_unknown_reference_type(void **state) {
    const char *string =
        "<references>\n"
        "  <registry>nginx:1.27</registry>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "No such reference type 'registry' at module 'container_images', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->references_count, 0);
}

void test_read_empty_archive_reference(void **state) {
    const char *string =
        "<references>\n"
        "  <archive></archive>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "Empty 'archive' reference at module 'container_images', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->references_count, 0);
}

void test_read_empty_reference_keeps_the_others(void **state) {
    const char *string =
        "<references>\n"
        "  <archive>/var/tmp/images/myapp.tar</archive>\n"
        "  <archive></archive>\n"
        "  <ref></ref>\n"
        "  <local>alpine:latest</local>\n"
        "</references>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "Empty 'archive' reference at module 'container_images', ignoring it.");
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "Empty 'ref' reference at module 'container_images', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    // The entries after an empty one are still read, and the empty ones are not stored.
    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->references_count, 2);
    assert_string_equal(data->references[0].type, "archive");
    assert_string_equal(data->references[0].value, "/var/tmp/images/myapp.tar");
    assert_string_equal(data->references[1].type, "local");
    assert_string_equal(data->references[1].value, "alpine:latest");
}

void test_read_disabled(void **state) {
    const char *string = "<enabled>no</enabled>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->enabled, 0);
}

void test_read_interval_hours(void **state) {
    const char *string = "<interval>2h</interval>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->interval, 7200);
}

void test_read_invalid_interval(void **state) {
    const char *string = "<interval>abc</interval>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid interval at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_interval_overflows_unit_multiplier(void **state) {
    const char *string = "<interval>100000000d</interval>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid interval at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_interval_does_not_fit_unsigned_int(void **state) {
    const char *string = "<interval>5000000000</interval>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid interval at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_invalid_enabled(void **state) {
    const char *string = "<enabled>maybe</enabled>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid content for tag 'enabled' at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_read_unknown_tag(void **state) {
    const char *string = "<unknown>value</unknown>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "No such tag 'unknown' at module 'container_images'.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);
}


void test_read_registry_auth(void **state) {
    const char *string =
        "<references>\n"
        "  <ref>ghcr.io/owner/app:1.0</ref>\n"
        "</references>\n"
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->references[0].type, "ref");
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].host, "ghcr.io");
    assert_string_equal(data->registries[0].user_key, "ghcr_user");
    assert_string_equal(data->registries[0].passkey_key, "ghcr_token");
}

void test_read_several_registries(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>a_user</user_keystore_key>\n"
        "    <passkey_keystore_key>a_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>other.example</host>\n"
        "    <user_keystore_key>b_user</user_keystore_key>\n"
        "    <passkey_keystore_key>b_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 2);
    assert_string_equal(data->registries[0].host, "ghcr.io");
    assert_string_equal(data->registries[1].host, "other.example");
}

void test_read_registry_with_only_a_passkey(void **state) {
    /* One of the two key names is enough to be a usable entry. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].user_key, "");
    assert_string_equal(data->registries[0].passkey_key, "ghcr_token");
}

void test_read_registry_without_host_is_skipped(void **state) {
    /* Skipped, not rejected: rejecting invalidates the whole module configuration and
     * stops wazuh-modulesd from starting, which is why every entry here is forgiving. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_registry_without_any_key_is_skipped(void **state) {
    /* A registry with no key names would be attempted anonymously anyway, so storing it
     * would be indistinguishable from having no entry at all. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_registry_unknown_tag_is_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <nonsense>x</nonsense>\n"
        "  </registry>\n"
        "  <nonsense>y</nonsense>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].host, "ghcr.io");
}

void test_read_empty_registry_auth_block(void **state) {
    const char *string = "<registry_auth></registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_ca_bundle(void **state) {
    const char *string = "<ca_bundle>/etc/ssl/certs/ca-certificates.crt</ca_bundle>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_string_equal(data->ca_bundle, "/etc/ssl/certs/ca-certificates.crt");
}

void test_read_empty_ca_bundle_is_skipped(void **state) {
    const char *string = "<ca_bundle></ca_bundle>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_null(data->ca_bundle);
}

void test_read_ca_bundle_last_one_wins(void **state) {
    /* The second value replaces the first rather than leaking it. */
    const char *string =
        "<ca_bundle>/first.crt</ca_bundle>\n"
        "<ca_bundle>/second.crt</ca_bundle>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_string_equal(data->ca_bundle, "/second.crt");
}

void test_read_defaults_have_no_registry_configuration(void **state) {
    const char *string = "<enabled>yes</enabled>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
    assert_null(data->registries);
    assert_null(data->ca_bundle);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_read_defaults, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_full_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_multiple_archive_references, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_every_reference_type_is_accepted, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_unknown_reference_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_archive_reference, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_reference_keeps_the_others, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_disabled, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_hours, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_interval, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_overflows_unit_multiplier, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_does_not_fit_unsigned_int, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_invalid_enabled, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_unknown_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_auth, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_several_registries, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_with_only_a_passkey, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_without_host_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_without_any_key_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_unknown_tag_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_registry_auth_block, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ca_bundle, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_ca_bundle_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ca_bundle_last_one_wins, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_defaults_have_no_registry_configuration, setup_test_read, teardown_test_read),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
