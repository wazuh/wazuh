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
};

#endif // _REMOTED_MODULE_HPP
