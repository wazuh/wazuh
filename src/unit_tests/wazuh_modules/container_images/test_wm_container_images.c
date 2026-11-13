/*
 * Copyright (C) Wazuh Inc.
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

cJSON *wm_container_images_dump(const wm_container_images_t *data);

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
                os_free(data->registries[i].region);
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

void test_read_registry_with_only_a_passkey_is_skipped(void **state) {
    /* Both keys are needed to authenticate, so an entry with one is reported while the
     * operator is editing it, and the message names the one that is missing. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'ghcr.io' at module 'container_images' names no 'user_keystore_key', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_registry_with_only_a_user_key_is_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'ghcr.io' at module 'container_images' names no 'passkey_keystore_key', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_registry_with_a_repeated_host_keeps_the_first(void **state) {
    /* The module uses the first entry for a host, so the second is reported instead of
     * being dropped without a word. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>first_user</user_keystore_key>\n"
        "    <passkey_keystore_key>first_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>second_user</user_keystore_key>\n"
        "    <passkey_keystore_key>second_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'ghcr.io' at module 'container_images' repeats a host already configured, ignoring it. The first entry is used.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].user_key, "first_user");
    assert_string_equal(data->registries[0].passkey_key, "first_token");
}

void test_read_registry_host_is_lowercased(void **state) {
    /* Host names are not case sensitive, and the module compares them in lower case, so
     * the entry is stored in the form that will match the references. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>GHCR.IO</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].host, "ghcr.io");
}

void test_read_registry_host_differing_only_in_case_is_a_repeat(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>first_user</user_keystore_key>\n"
        "    <passkey_keystore_key>first_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>GHCR.io</host>\n"
        "    <user_keystore_key>second_user</user_keystore_key>\n"
        "    <passkey_keystore_key>second_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'ghcr.io' at module 'container_images' repeats a host already configured, ignoring it. The first entry is used.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].user_key, "first_user");
}

void test_read_registry_host_with_a_scheme_is_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>https://ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'https://ghcr.io' at module 'container_images' must name a bare host such as 'ghcr.io', without a scheme, a path or whitespace, ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_registry_host_with_a_path_is_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io/owner</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'ghcr.io/owner' at module 'container_images' must name a bare host such as 'ghcr.io', without a scheme, a path or whitespace, ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_registry_host_with_whitespace_is_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr .io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The 'registry' entry for 'ghcr .io' at module 'container_images' must name a bare host such as 'ghcr.io', without a scheme, a path or whitespace, ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
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
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
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

#define ECR_HOST "123456789012.dkr.ecr.us-east-1.amazonaws.com"

void test_read_ecr_registry(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "    <region>us-east-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].host, ECR_HOST);
    assert_string_equal(data->registries[0].user_key, "ecr_key_id");
    assert_string_equal(data->registries[0].passkey_key, "ecr_secret");
    assert_string_equal(data->registries[0].region, "us-east-1");
    assert_int_equal(data->registries[0].aws, 1);
}

void test_read_ecr_registry_without_region(void **state) {
    /* The region is optional: the host names one. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].region, "");
    assert_int_equal(data->registries[0].aws, 1);
}

void test_read_ecr_registry_of_china_and_other_regions(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn</host>\n"
        "    <access_key_id_keystore_key>a</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>b</secret_access_key_keystore_key>\n"
        "    <region>cn-north-1</region>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>123456789012.dkr.ecr.us-gov-west-1.amazonaws.com</host>\n"
        "    <access_key_id_keystore_key>c</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>d</secret_access_key_keystore_key>\n"
        "    <region>us-gov-west-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 2);
    assert_string_equal(data->registries[0].region, "cn-north-1");
    assert_string_equal(data->registries[1].region, "us-gov-west-1");
}

void test_read_ecr_registry_missing_a_key_is_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <region>us-east-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));

    for (int i = 0; i < 3; i++) {
        expect_any(__wrap__mtwarn, tag);
        expect_string(__wrap__mtwarn, formatted_msg,
                      "The 'registry' entry for '" ECR_HOST "' at module 'container_images' needs both 'access_key_id_keystore_key' and 'secret_access_key_keystore_key', ignoring it.");
    }

    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_ecr_registry_with_an_invalid_region_is_skipped(void **state) {
    (void)state;

    const char *regions[] = {"us-east-1.attacker.example", "US-EAST-1", "us east 1", "useast1", "us-east", "eu-west-1/x", "us-e4st-1", "us-12-1"};

    for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
        char string[512];
        snprintf(string, sizeof(string),
                 "<registry_auth>\n"
                 "  <registry>\n"
                 "    <host>" ECR_HOST "</host>\n"
                 "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
                 "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
                 "    <region>%s</region>\n"
                 "  </registry>\n"
                 "</registry_auth>\n", regions[i]);

        test_structure *test = calloc(1, sizeof(test_structure));
        test->module = calloc(1, sizeof(wmodule));
        test->nodes = string_to_xml_node(string, &(test->xml));

        expect_any(__wrap__mtwarn, tag);
        expect_string(__wrap__mtwarn, formatted_msg,
                      "The 'registry' entry for '" ECR_HOST "' at module 'container_images' has an invalid 'region', ignoring it.");

        assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);
        assert_int_equal(((wm_container_images_t *)test->module->data)->registries_count, 0);

        teardown_test_read((void **)&test);
    }
}

void test_read_ecr_tags_mixed_with_basic_tags_are_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <user_keystore_key>u</user_keystore_key>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg,
                  "The 'registry' entry for '" ECR_HOST "' at module 'container_images' mixes 'user_keystore_key' and 'passkey_keystore_key' with the Amazon ECR tags, ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_ecr_tags_on_a_host_that_is_not_amazon_are_skipped(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>public.ecr.aws</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>evil.example.com</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
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

void test_read_basic_tags_on_an_amazon_host_are_skipped(void **state) {
    /* The user and passkey of a registry would be sent to AWS as an access key pair, which
     * is never what was meant, so the entry is refused with the tags to use instead. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <user_keystore_key>u</user_keystore_key>\n"
        "    <passkey_keystore_key>p</passkey_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg,
                  "The 'registry' entry for '" ECR_HOST "' at module 'container_images' needs 'access_key_id_keystore_key' and 'secret_access_key_keystore_key' for an Amazon ECR registry, ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 0);
}

void test_read_ecr_and_ghcr_registries_side_by_side(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 2);
    assert_int_equal(data->registries[0].aws, 0);
    assert_string_equal(data->registries[0].region, "");
    assert_int_equal(data->registries[1].aws, 1);
}

void test_read_ghcr_registry_with_a_stray_region_is_kept(void **state) {
    /* The region means nothing for GHCR. The entry worked before the tag existed, so it is kept
     * and only the tag is ignored, rather than a private repository turning anonymous. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "    <region>us-east-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg,
                  "The 'region' tag inside 'registry' for 'ghcr.io' at module 'container_images' applies only to an Amazon ECR registry, ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_int_equal(data->registries[0].aws, 0);
    assert_string_equal(data->registries[0].user_key, "ghcr_user");
    assert_string_equal(data->registries[0].passkey_key, "ghcr_token");
    assert_string_equal(data->registries[0].region, "");
}

void test_read_ecr_host_is_read_in_lower_case(void **state) {
    /* The Amazon check and the module's own comparison both look at the host in lower case. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>123456789012.DKR.ECR.US-EAST-1.AMAZONAWS.COM</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].host, ECR_HOST);
    assert_int_equal(data->registries[0].aws, 1);
}

void test_read_ecr_host_with_a_scheme_or_a_path_is_skipped(void **state) {
    const char *hosts[] = {"https://" ECR_HOST, ECR_HOST "/my-backend", ECR_HOST " extra"};

    (void)state;

    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        char string[512];
        snprintf(string, sizeof(string),
                 "<registry_auth>\n"
                 "  <registry>\n"
                 "    <host>%s</host>\n"
                 "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
                 "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
                 "  </registry>\n"
                 "</registry_auth>\n", hosts[i]);

        test_structure *test = calloc(1, sizeof(test_structure));
        test->module = calloc(1, sizeof(wmodule));
        test->nodes = string_to_xml_node(string, &(test->xml));

        char message[512];
        snprintf(message, sizeof(message),
                 "The 'registry' entry for '%s' at module 'container_images' must name a bare host such as 'ghcr.io', without a scheme, a path or whitespace, ignoring it.", hosts[i]);

        expect_any(__wrap__mtwarn, tag);
        expect_string(__wrap__mtwarn, formatted_msg, message);
        assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);
        assert_int_equal(((wm_container_images_t *)test->module->data)->registries_count, 0);
        teardown_test_read((void **)&test);
    }
}

void test_read_a_second_ecr_entry_for_a_host_is_ignored(void **state) {
    /* The first entry is the one the module uses, as for any other registry, and a host
     * written in another case is the same host. */
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>first_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>first_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>123456789012.DKR.ECR.US-EAST-1.AMAZONAWS.COM</host>\n"
        "    <access_key_id_keystore_key>second_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>second_secret</secret_access_key_keystore_key>\n"
        "    <region>eu-west-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg,
                  "The 'registry' entry for '" ECR_HOST "' at module 'container_images' repeats a host already configured, ignoring it. The first entry is used.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    wm_container_images_t *data = (wm_container_images_t *)test->module->data;
    assert_int_equal(data->registries_count, 1);
    assert_string_equal(data->registries[0].user_key, "first_id");
    assert_string_equal(data->registries[0].passkey_key, "first_secret");
    assert_string_equal(data->registries[0].region, "");
}

void test_read_ecr_entry_with_only_one_aws_key_is_skipped_whichever_one(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "    <region>us-east-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg,
                  "The 'registry' entry for '" ECR_HOST "' at module 'container_images' needs both 'access_key_id_keystore_key' and 'secret_access_key_keystore_key', ignoring it.");
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);
    assert_int_equal(((wm_container_images_t *)test->module->data)->registries_count, 0);
}

void test_read_aws_tags_on_another_amazon_host_are_skipped(void **state) {
    /* Hosts under amazonaws.com that are not a private ECR registry can never match a
     * reference, so the entry is refused where the operator is editing it. */
    const char *hosts[] = {"s3.amazonaws.com", "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com",
                           "dkr.ecr.us-east-1.amazonaws.com", "12345678901.dkr.ecr.us-east-1.amazonaws.com",
                           "123456789012.dkr.ecr.nowhere.amazonaws.com", "api.ecr.us-east-1.amazonaws.com"};

    (void)state;

    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        char string[512];
        char message[512];
        snprintf(string, sizeof(string),
                 "<registry_auth>\n"
                 "  <registry>\n"
                 "    <host>%s</host>\n"
                 "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
                 "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
                 "  </registry>\n"
                 "</registry_auth>\n", hosts[i]);
        snprintf(message, sizeof(message),
                 "The 'registry' entry for '%s' at module 'container_images' uses Amazon ECR tags, which apply only to a private ECR registry such as '<account>.dkr.ecr.<region>.amazonaws.com', ignoring it.", hosts[i]);

        test_structure *test = calloc(1, sizeof(test_structure));
        test->module = calloc(1, sizeof(wmodule));
        test->nodes = string_to_xml_node(string, &(test->xml));

        expect_any(__wrap__mtwarn, tag);
        expect_string(__wrap__mtwarn, formatted_msg, message);
        assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);
        assert_int_equal(((wm_container_images_t *)test->module->data)->registries_count, 0);
        teardown_test_read((void **)&test);
    }
}

void test_dump_names_the_keys_and_never_a_value(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>ghcr.io</host>\n"
        "    <user_keystore_key>ghcr_user</user_keystore_key>\n"
        "    <passkey_keystore_key>ghcr_token</passkey_keystore_key>\n"
        "  </registry>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "    <region>eu-west-1</region>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    cJSON *dump = wm_container_images_dump((wm_container_images_t *)test->module->data);
    cJSON *registries = cJSON_GetObjectItem(cJSON_GetObjectItem(dump, "container_images"), "registry_auth");
    assert_int_equal(cJSON_GetArraySize(registries), 2);

    cJSON *ghcr = cJSON_GetArrayItem(registries, 0);
    assert_string_equal(cJSON_GetObjectItem(ghcr, "user_keystore_key")->valuestring, "ghcr_user");
    assert_string_equal(cJSON_GetObjectItem(ghcr, "passkey_keystore_key")->valuestring, "ghcr_token");
    assert_null(cJSON_GetObjectItem(ghcr, "access_key_id_keystore_key"));
    assert_null(cJSON_GetObjectItem(ghcr, "region"));

    cJSON *ecr = cJSON_GetArrayItem(registries, 1);
    assert_string_equal(cJSON_GetObjectItem(ecr, "access_key_id_keystore_key")->valuestring, "ecr_key_id");
    assert_string_equal(cJSON_GetObjectItem(ecr, "secret_access_key_keystore_key")->valuestring, "ecr_secret");
    assert_string_equal(cJSON_GetObjectItem(ecr, "region")->valuestring, "eu-west-1");
    assert_null(cJSON_GetObjectItem(ecr, "user_keystore_key"));

    cJSON_Delete(dump);
}

void test_dump_omits_the_region_when_none_is_configured(void **state) {
    const char *string =
        "<registry_auth>\n"
        "  <registry>\n"
        "    <host>" ECR_HOST "</host>\n"
        "    <access_key_id_keystore_key>ecr_key_id</access_key_id_keystore_key>\n"
        "    <secret_access_key_keystore_key>ecr_secret</secret_access_key_keystore_key>\n"
        "  </registry>\n"
        "</registry_auth>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_container_images_read(&(test->xml), test->nodes, test->module), 0);

    cJSON *dump = wm_container_images_dump((wm_container_images_t *)test->module->data);
    cJSON *registries = cJSON_GetObjectItem(cJSON_GetObjectItem(dump, "container_images"), "registry_auth");

    assert_null(cJSON_GetObjectItem(cJSON_GetArrayItem(registries, 0), "region"));

    cJSON_Delete(dump);
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
        cmocka_unit_test_setup_teardown(test_read_registry_with_only_a_passkey_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_with_only_a_user_key_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_with_a_repeated_host_keeps_the_first, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_host_is_lowercased, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_host_differing_only_in_case_is_a_repeat, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_host_with_a_scheme_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_host_with_a_path_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_host_with_whitespace_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_without_host_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_without_any_key_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_registry_unknown_tag_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_registry_auth_block, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ca_bundle, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_empty_ca_bundle_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ca_bundle_last_one_wins, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_defaults_have_no_registry_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_registry, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_registry_without_region, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_registry_of_china_and_other_regions, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_registry_missing_a_key_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_registry_with_an_invalid_region_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_tags_mixed_with_basic_tags_are_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_tags_on_a_host_that_is_not_amazon_are_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_basic_tags_on_an_amazon_host_are_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_and_ghcr_registries_side_by_side, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ghcr_registry_with_a_stray_region_is_kept, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_host_is_read_in_lower_case, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_host_with_a_scheme_or_a_path_is_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_a_second_ecr_entry_for_a_host_is_ignored, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_ecr_entry_with_only_one_aws_key_is_skipped_whichever_one, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_aws_tags_on_another_amazon_host_are_skipped, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_dump_names_the_keys_and_never_a_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_dump_omits_the_region_when_none_is_configured, setup_test_read, teardown_test_read),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
