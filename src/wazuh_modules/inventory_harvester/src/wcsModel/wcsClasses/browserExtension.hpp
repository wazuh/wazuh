/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * August 16, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BROWSER_EXTENSION_WCS_MODEL_HPP
#define _BROWSER_EXTENSION_WCS_MODEL_HPP

#include "hash.hpp"
#include "reflectiveJson.hpp"
#include <string_view>

struct BrowserExtension final
{
    struct Profile final
    {
        std::string_view name;
        std::string_view path;
        bool referenced = false;
        REFLECTABLE(MAKE_FIELD("name", &Profile::name),
                    MAKE_FIELD("path", &Profile::path),
                    MAKE_FIELD("referenced", &Profile::referenced));
    };

    struct Browser final
    {
        std::string_view name;
        Profile profile;
        REFLECTABLE(MAKE_FIELD("name", &Browser::name), MAKE_FIELD("profile", &Browser::profile));
    };

    struct Hash final
    {
        std::string_view sha256;
        REFLECTABLE(MAKE_FIELD("sha256", &Hash::sha256));
    };

    struct File final
    {
        Hash hash;
        REFLECTABLE(MAKE_FIELD("hash", &File::hash));
    };

    struct Package final
    {
        bool autoupdate = false;
        std::string_view build_version;
        std::string_view description;
        bool enabled = false;
        bool visible = false;
        bool from_webstore = false;
        std::string_view id;
        std::string_view installed;
        std::string_view name;
        std::string_view path;
        std::vector<std::string_view> permissions;
        bool persistent = false;
        std::string_view reference;
        std::string_view type;
        std::string_view vendor;
        std::string_view version;
        REFLECTABLE(MAKE_FIELD("autoupdate", &Package::autoupdate),
                    MAKE_FIELD("build_version", &Package::build_version),
                    MAKE_FIELD("description", &Package::description),
                    MAKE_FIELD("enabled", &Package::enabled),
                    MAKE_FIELD("visible", &Package::visible),
                    MAKE_FIELD("from_webstore", &Package::from_webstore),
                    MAKE_FIELD("id", &Package::id),
                    MAKE_FIELD("installed", &Package::installed),
                    MAKE_FIELD("name", &Package::name),
                    MAKE_FIELD("path", &Package::path),
                    MAKE_FIELD("permissions", &Package::permissions),
                    MAKE_FIELD("persistent", &Package::persistent),
                    MAKE_FIELD("reference", &Package::reference),
                    MAKE_FIELD("type", &Package::type),
                    MAKE_FIELD("vendor", &Package::vendor),
                    MAKE_FIELD("version", &Package::version));
    };

    struct User final
    {
        std::string_view id;
        REFLECTABLE(MAKE_FIELD("id", &User::id));
    };
};

#endif // _BROWSER_EXTENSION_WCS_MODEL_HPP
