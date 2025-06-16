/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WCS_USER_HPP
#define _WCS_USER_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Host final {
    std::string_view ip;
    REFLECTABLE(MAKE_FIELD("ip", &Host::ip));
};

struct Login final {
    bool status = false;
    std::string_view tty;
    std::string_view type;
    REFLECTABLE(MAKE_FIELD("status", &Login::status),
                MAKE_FIELD("tty", &Login::tty),
                MAKE_FIELD("type", &Login::type));
};

struct Process final {
    long pid = 0;
    REFLECTABLE(MAKE_FIELD("pid", &Process::pid));
};

struct AuthFailures final {
    int count = 0;
    std::string_view timestamp;
    REFLECTABLE(MAKE_FIELD("count", &AuthFailures::count),
                MAKE_FIELD("timestamp", &AuthFailures::timestamp));
};

struct UserGroupInfo final {
    unsigned long id = 0;
    long id_signed = 0;
    REFLECTABLE(MAKE_FIELD("id", &UserGroupInfo::id),
                MAKE_FIELD("id_signed", &UserGroupInfo::id_signed));
};

struct Password final {
    std::string_view expiration_date;
    std::string_view hash_algorithm;
    int inactive_days = 0;
    long last_change = 0;
    std::string_view last_set_time;
    int max_days_between_changes = 0;
    int min_days_between_changes = 0;
    std::string_view status;
    int warning_days_before_expiration = 0;
    REFLECTABLE(MAKE_FIELD("expiration_date", &Password::expiration_date),
                MAKE_FIELD("hash_algorithm", &Password::hash_algorithm),
                MAKE_FIELD("inactive_days", &Password::inactive_days),
                MAKE_FIELD("last_change", &Password::last_change),
                MAKE_FIELD("last_set_time", &Password::last_set_time),
                MAKE_FIELD("max_days_between_changes", &Password::max_days_between_changes),
                MAKE_FIELD("min_days_between_changes", &Password::min_days_between_changes),
                MAKE_FIELD("status", &Password::status),
                MAKE_FIELD("warning_days_before_expiration", &Password::warning_days_before_expiration));
};

struct User final {
    AuthFailures auth_failures;
    std::string_view created;
    std::string_view full_name;
    UserGroupInfo group;
    std::string_view groups;
    std::string_view home;
    std::string_view id;
    bool is_hidden = false;
    bool is_remote = false;
    std::string_view last_login;
    std::string_view name;
    Password password;
    std::string_view roles;
    std::string_view shell;
    std::string_view type;
    long uid_signed = 0;
    std::string_view uuid;

    REFLECTABLE(MAKE_FIELD("auth_failures", &User::auth_failures),
                MAKE_FIELD("created", &User::created),
                MAKE_FIELD("full_name", &User::full_name),
                MAKE_FIELD("group", &User::group),
                MAKE_FIELD("groups", &User::groups),
                MAKE_FIELD("home", &User::home),
                MAKE_FIELD("id", &User::id),
                MAKE_FIELD("is_hidden", &User::is_hidden),
                MAKE_FIELD("is_remote", &User::is_remote),
                MAKE_FIELD("last_login", &User::last_login),
                MAKE_FIELD("name", &User::name),
                MAKE_FIELD("password", &User::password),
                MAKE_FIELD("roles", &User::roles),
                MAKE_FIELD("shell", &User::shell),
                MAKE_FIELD("type", &User::type),
                MAKE_FIELD("uid_signed", &User::uid_signed),
                MAKE_FIELD("uuid", &User::uuid));
};

#endif // _WCS_USER_HPP
