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
        /// Parses the text. A malformed non-comment line is Cause::InvalidConfig naming its line number.
        static Outcome<KeyValueConfigSource> parse(std::string_view text, std::string indexerSectionJson);

        KeyValueConfigSource() = default;

        std::optional<std::string> raw(std::string_view key) const override;
        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override;
        std::string indexerSectionJson() const override;

    private:
        std::map<std::string, std::string, std::less<>> m_values;
        std::string m_indexerSectionJson;
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_KEY_VALUE_CONFIG_SOURCE_HPP
