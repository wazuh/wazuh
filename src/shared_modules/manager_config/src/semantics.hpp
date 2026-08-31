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

    /**
     * Cross-field rules the schema cannot express (RF-4), applied to the effective document:
     *  - remote.https: certificate and key both set or both empty;
     *  - remote.https.global_prefix: no "." or ".." path segments;
     *  - remote.legacy.port (when enabled), remote.https.port, auth.port (when authd enabled) and
     *    cluster.port are pairwise distinct;
     *  - when options.checkFiles: every non-empty certificate/key/CA path exists (relative to options.home).
     * All failures are fatal and reported with the JSON pointer of the offending option.
     */
    std::optional<Error> checkSemantics(const rapidjson::Document& effective, const LoadOptions& options);

} // namespace manager_config::detail
