/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_HPP
#define _REMOTED_MODULE_HPP

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "remoted_module.h"
#include "singleton.hpp"
#include <cstdarg>
#include <cstddef>
#include <functional>

/**
 * @brief Public C++ facade for the remoted module.
 *
 * Thin Singleton mirroring the InventorySync pattern: the extern "C" shims call
 * into this class, which delegates to the internal RemotedModuleFacade that owns
 * the worker thread.
 */
class EXPORTED RemotedModule final : public Singleton<RemotedModule>
{
public:
    /**
     * @brief Start the module.
     *
     * Throws if the HTTPS transport fails to start (e.g. the TLS
     * certificate/key are not in place). Not caught here: there is no retry,
     * and the caller must let it propagate.
     *
     * @param logFunction   Log function to be used by the module.
     * @param configuration Module configuration.
     */
    void
    start(const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
              logFunction,
          const remoted_module_config_t& configuration) const;

    /**
     * @brief Stop the module.
     */
    void stop() const;

    /**
     * @brief Whether the configured CA signs the certificate the HTTPS listener serves.
     *
     * @return 1 signs it, 0 explicitly does not, -1 unknown. See RemotedModuleFacade::tlsCaMatchesLeaf()
     *         for why -1 must be treated as "proceed" rather than as a refusal.
     */
    int tlsCaMatchesLeaf() const;

    /**
     * @brief The one CA certificate that signs the certificate the HTTPS listener serves,
     *        re-serialised into @p buffer -- a single certificate, no publication block.
     *
     * @param buffer Destination. Not NUL-terminated: the return value is the length.
     * @param capacity Bytes available at @p buffer.
     * @return Bytes written (> 0), 0 when there is nothing to deliver, -1 when @p capacity is too
     *         small. See RemotedModuleFacade::tlsCaLeafSignerPem() for why the legacy WPK delivery
     *         needs one certificate rather than the bundle.
     */
    int tlsCaLeafSignerPem(char* buffer, std::size_t capacity) const;
};

#endif // _REMOTED_MODULE_HPP
