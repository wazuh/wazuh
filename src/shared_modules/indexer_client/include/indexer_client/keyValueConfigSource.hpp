/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CLIENT_KEY_VALUE_CONFIG_SOURCE_HPP
#define _INDEXER_CLIENT_KEY_VALUE_CONFIG_SOURCE_HPP

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "iConfigSource.hpp"
#include "types.hpp"

namespace indexer_client
{
    /// IConfigSource over the text of an internal-options file (`key=value` lines, `#` comments) plus the `<indexer>`
    /// section JSON given by the caller. The caller reads the file (modulesd's C side, E7); this class only parses
    /// text.
    class INDEXER_CLIENT_API KeyValueConfigSource final : public IConfigSource
    {
    public:
        /// Parses the text, judged per key like wazuh's C internal-options reader but stricter under the prefix (a
        /// malformed line is fatal there; C skips it). Parsing never fails on a line: a non-comment line without '='
        /// or with an empty value is recorded (problem() names its line) and only fails RuntimeConfig::from() when its
        /// key is under that process's prefix.
        static Outcome<KeyValueConfigSource> parse(std::string_view text, std::string indexerSectionJson);

        KeyValueConfigSource() = default;

        std::optional<std::string> raw(std::string_view key) const override;
        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override;
        std::string indexerSectionJson() const override;
        std::optional<std::string> problem(std::string_view key) const override;

    private:
        std::map<std::string, std::string, std::less<>> m_values;
        std::map<std::string, std::string, std::less<>> m_problems; ///< key -> "line N: ..." (first occurrence).
        std::string m_indexerSectionJson;
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_KEY_VALUE_CONFIG_SOURCE_HPP
