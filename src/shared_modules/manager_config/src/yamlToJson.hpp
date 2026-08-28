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

    /// Limits applied before parsing (RNF-4).
    constexpr std::size_t MAX_YAML_BYTES = 1024 * 1024;
    constexpr int MAX_YAML_DEPTH = 16;

    /**
     * Parse a YAML text into a rapidjson document following the YAML 1.2 core schema (true/false, integers,
     * floats, null; everything else is a string). Rejects: more than one document, anchors/aliases, explicit
     * tags, non-mapping roots and documents deeper than MAX_YAML_DEPTH. An empty text (or only comments) is
     * the empty mapping.
     */
    std::optional<Error> yamlToJson(std::string_view yamlText, rapidjson::Document& out);

} // namespace manager_config::detail
