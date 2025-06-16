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
#include <string_view> // Added for std::string_view
#include <vector>      // Kept for std::vector
// #include <string> // Should be removed if present previously

// Forward declaration if Host is in a different header or define basic Host here
// Assuming Host struct is simple and defined here. If it's complex and shared, it might need its own file.
struct Host {
    std::string_view ip; // Changed
    REFLECTABLE(MAKE_FIELD("ip", &Host::ip));
};

struct Login {
    bool status = false;
    std::string_view tty; // Changed
    std::string_view type; // Changed
    REFLECTABLE(MAKE_FIELD("status", &Login::status),
                MAKE_FIELD("tty", &Login::tty),
                MAKE_FIELD("type", &Login::type));
};

struct Process { // Assuming Process remains simple with only pid
    long pid = 0;
    REFLECTABLE(MAKE_FIELD("pid", &Process::pid));
};

struct AuthFailures {
    int count = 0;
    std::string_view timestamp; // Changed (Assuming ISO8601 date string)
    REFLECTABLE(MAKE_FIELD("count", &AuthFailures::count),
                MAKE_FIELD("timestamp", &AuthFailures::timestamp));
};

// UserGroupInfo is fine as it only contains numeric types and REFLECTABLE
struct UserGroupInfo {
    unsigned long id = 0;
    long id_signed = 0;
    REFLECTABLE(MAKE_FIELD("id", &UserGroupInfo::id),
                MAKE_FIELD("id_signed", &UserGroupInfo::id_signed));
};

struct Password {
    std::string_view expiration_date; // Changed (Assuming ISO8601 date string)
    std::string_view hash_algorithm;  // Changed
    int inactive_days = 0;
    long last_change = 0;
    std::string_view last_set_time;   // Changed (Assuming ISO8601 date string)
    int max_days_between_changes = 0;
    int min_days_between_changes = 0;
    std::string_view status;          // Changed
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

struct User {
    AuthFailures auth_failures;
    std::string_view created; // Changed (Assuming ISO8601 date string)
    std::string_view full_name; // Changed
    UserGroupInfo group;
    std::vector<std::string_view> groups; // Changed to vector of string_view
    std::string_view home;    // Changed
    std::string_view id;      // Changed
    bool is_hidden = false;
    bool is_remote = false;
    std::string_view last_login; // Changed (Assuming ISO8601 date string)
    std::string_view name;       // Changed
    Password password;
    std::vector<std::string_view> roles; // Changed to vector of string_view
    std::string_view shell;   // Changed
    std::string_view type;    // Changed
    long uid_signed = 0;
    std::string_view uuid;    // Changed

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
