/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#include "manager_config/manager_config_c.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
#include <string>

#include "manager_config/manager_config.hpp"

struct mconf
{
    manager_config::Document document;
};

namespace
{

    void setError(char* err, size_t errlen, const std::string& message)
    {
        if (err != nullptr && errlen > 0)
        {
            std::snprintf(err, errlen, "%s", message.c_str());
        }
    }

    manager_config::LoadOptions options(const char* home)
    {
        manager_config::LoadOptions opts;
        if (home != nullptr && *home != '\0')
        {
            opts.home = home;
        }
        return opts;
    }

    char* duplicate(const std::string& text)
    {
        char* out = static_cast<char*>(std::malloc(text.size() + 1));
        if (out != nullptr)
        {
            std::memcpy(out, text.c_str(), text.size() + 1);
        }
        return out;
    }

} // namespace

extern "C"
{

    int mconf_load(const char* path, const char* home, mconf_t** out, char* err, size_t errlen)
    {
        if (path == nullptr || out == nullptr)
        {
            setError(err, errlen, "mconf_load: invalid arguments");
            return -1;
        }
        *out = nullptr;
        try
        {
            auto result = manager_config::Document::load(path, options(home));
            if (auto* error = std::get_if<manager_config::Error>(&result))
            {
                setError(err, errlen, error->what());
                return -1;
            }
            *out = new mconf {std::move(std::get<manager_config::Document>(result))};
            return 0;
        }
        catch (const std::exception& e)
        {
            setError(err, errlen, std::string {"mconf_load: "} + e.what());
            return -1;
        }
    }

    int mconf_validate(const char* path, const char* home, char* err, size_t errlen)
    {
        if (path == nullptr)
        {
            setError(err, errlen, "mconf_validate: invalid arguments");
            return -1;
        }
        try
        {
            if (auto error = manager_config::validateFile(path, options(home)))
            {
                setError(err, errlen, error->what());
                return -1;
            }
            return 0;
        }
        catch (const std::exception& e)
        {
            setError(err, errlen, std::string {"mconf_validate: "} + e.what());
            return -1;
        }
    }

    char* mconf_section_json(const mconf_t* conf, const char* section)
    {
        if (conf == nullptr || section == nullptr)
        {
            return nullptr;
        }
        try
        {
            const std::string json = conf->document.sectionJson(section);
            return json.empty() ? nullptr : duplicate(json);
        }
        catch (const std::exception&)
        {
            return nullptr;
        }
    }

    char* mconf_document_json(const mconf_t* conf)
    {
        if (conf == nullptr)
        {
            return nullptr;
        }
        try
        {
            return duplicate(conf->document.documentJson());
        }
        catch (const std::exception&)
        {
            return nullptr;
        }
    }

    void mconf_free(mconf_t* conf)
    {
        delete conf;
    }
}
