/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */
#pragma once

#include <rapidjson/document.h>

namespace manager_config::detail
{

    /**
     * Fill the document with the `default` values declared in the schema (draft-04, `properties` tree).
     * Algorithm (replicated by the Python framework): for every property of an object schema that is missing
     * in the document, insert its `default` when declared, otherwise an empty object when the property is an
     * object schema; then recurse into every object property (present or just inserted) so nested defaults
     * are filled too. Arrays and scalars are never modified.
     */
    void fillDefaults(const rapidjson::Value& schema,
                      const rapidjson::Value& schemaRoot,
                      rapidjson::Value& node,
                      rapidjson::Document::AllocatorType& allocator);

} // namespace manager_config::detail
