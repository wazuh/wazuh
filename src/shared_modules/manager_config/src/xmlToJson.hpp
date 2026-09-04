/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#pragma once

#include <rapidjson/document.h>

#include <optional>
#include <string>
#include <string_view>

#include "manager_config/manager_config.hpp"

namespace manager_config::detail
{

    /// Limits applied before parsing (RNF-3).
    constexpr std::size_t MAX_XML_BYTES = 1024 * 1024;
    constexpr int MAX_XML_DEPTH = 16;

    /**
     * Parse a strict-XML text into the canonical rapidjson document the schema validates (the same shape the
     * YAML backend produced): exactly one <wazuh_config> root, entities decoded, no raw '&', no legacy
     * comments. Typing is driven by the embedded schema: yes/no become booleans, digit-only text becomes an
     * integer where the schema allows one, repeated or comma-separated values become arrays, the attribute
     * forms of the historic dialect (<backup database="...">, <disconnected_time enabled="...">) become
     * nested objects, and enums declared in lowercase are normalized. Unknown elements are converted
     * literally so the schema rejects them with their JSON pointer.
     */
    std::optional<Error> xmlToJson(std::string_view xmlText, rapidjson::Document& out);

} // namespace manager_config::detail
