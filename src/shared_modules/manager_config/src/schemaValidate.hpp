/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#pragma once

#include <rapidjson/document.h>

#include <optional>

#include "manager_config/manager_config.hpp"

namespace manager_config::detail
{

    /// The embedded schema parsed once (draft-04). Throws std::runtime_error if the embedded text is broken.
    const rapidjson::Document& schemaDocument();

    /// Validate a raw document against the embedded schema. The error carries the JSON pointer of the
    /// offending value and the violated keyword ("/remote/https/port: does not satisfy 'maximum'").
    std::optional<Error> validateAgainstSchema(const rapidjson::Document& document);

} // namespace manager_config::detail
