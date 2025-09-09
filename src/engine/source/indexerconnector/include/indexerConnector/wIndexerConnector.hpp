/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * June 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WINDEXER_CONNECTOR_HPP
#define _WINDEXER_CONNECTOR_HPP

#include <string>
#include <string_view>


namespace wiconnector
{
    class WIndexerConnector {
    public:
        WIndexerConnector() = default;
        WIndexerConnector(std::string_view host, int port);
        ~WIndexerConnector() = default;
    };
};

#endif // _WINDEXER_CONNECTOR_HPP
