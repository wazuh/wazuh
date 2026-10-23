/*
 * Wazuh modulesd indexer client runtime bridge
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WM_INDEXER_RUNTIME_HPP
#define _WM_INDEXER_RUNTIME_HPP

#include <functional>

#include "indexer_client/types.hpp"

namespace wmir
{
    /// Reads the indexer credentials; production reads Keystore::get("indexer", "username"|"password"). May throw.
    using CredentialReader = std::function<indexer_client::Credentials()>;

    /// Test seam: replaces the credential reader (an empty function restores the keystore reader).
    void setCredentialReaderForTests(CredentialReader reader);

    /// Test seam: shuts a running runtime down (owner thread), forgets the configuration and restores the keystore
    /// reader.
    void resetForTests();
} // namespace wmir

#endif // _WM_INDEXER_RUNTIME_HPP
