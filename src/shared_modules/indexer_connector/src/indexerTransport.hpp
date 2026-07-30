/*
 * Wazuh - Indexer connector transport settings.
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_TRANSPORT_HPP
#define _INDEXER_TRANSPORT_HPP

#include "external/nlohmann/json.hpp"
#include "loggerHelper.h"
#include "secureCommunication.hpp"

/**
 * @brief Parses `ssl.*`, merges the CA root certificates and reads the indexer credentials from the
 *        keystore, returning the authenticated transport settings built from all of it.
 *
 * ONE definition shared by both connector variants and by IndexerSession. This block used to be
 * duplicated byte-for-byte between indexerConnectorSyncImpl.hpp and indexerConnectorAsyncImpl.hpp,
 * so "both variants validate identically" was a property maintained by hand. Here it is structural.
 *
 * Deliberate side effect of living in a single translation unit: the credential mutex and the
 * cached username/password are now unique process-wide, so `queue/keystore` is opened ONCE per
 * process instead of once per connector class. Same semantics as before -- rotating the credentials
 * always required a restart, because the cache never expires -- with half the RocksDB opens.
 *
 * @param config The `<indexer>` configuration block. Only `ssl.certificate_authorities`,
 *               `ssl.certificate` and `ssl.key` are read; `hosts` is NOT validated here (callers
 *               check it first, since it is the cheaper check).
 * @param logFn Logger used for the "no credentials in the keystore" warnings.
 * @return Transport settings ready to hand to a server selector or an HTTP request.
 *
 * @throw IndexerConnectorException if a single configured CA file does not exist on disk.
 * @throw std::runtime_error from Utils::CertHelper if merging several CA files fails.
 */
SecureCommunication buildSecureCommunication(const nlohmann::json& config, const LogFn& logFn);

#endif // _INDEXER_TRANSPORT_HPP
