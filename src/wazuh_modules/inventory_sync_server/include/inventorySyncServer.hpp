/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_SERVER_HPP
#define _INVENTORY_SYNC_SERVER_HPP

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "inventory_sync_server.h"
#include "singleton.hpp"
#include <cstdarg>
#include <functional>
#include <json.hpp>

/**
 * @brief Public C++ facade for the inventory_sync_server module.
 *
 * Thin Singleton mirroring RemotedModule/InventorySync: the extern "C" shims call into
 * this class, which delegates to the internal InventorySyncServerFacade that owns the
 * worker thread.
 *
 * The name matters. libinventory_sync.so already exports `InventorySync` with default
 * visibility, and both .so files are loaded into the SAME modulesd process -- so a
 * same-named class here would be interposed by the dynamic linker against that one.
 * Everything this module adds is either `InventorySyncServer*` or inside namespace
 * `invsync`.
 */
class EXPORTED InventorySyncServer final : public Singleton<InventorySyncServer>
{
public:
    /**
     * @brief Start the module.
     *
     * @param logFunction   Log function to be used by the module.
     * @param configuration Module configuration.
     * @param indexerConfig The <indexer> block, already converted out of cJSON and owned by
     *                      the module. Taken separately from @p configuration (whose own
     *                      `indexer` field is cleared by the caller) so that no cJSON type
     *                      reaches the facade and no borrowed pointer outlives the start()
     *                      call -- the conversion happens once, in the extern "C" shim.
     *
     * @return false when the module cannot start and retrying would never help (see
     *         inventory_sync_server_start()). An unreachable indexer returns true.
     */
    bool
    start(const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
              logFunction,
          const inventory_sync_server_config_t& configuration,
          nlohmann::json indexerConfig) const;

    /**
     * @brief Stop the module.
     */
    void stop() const;
};

#endif // _INVENTORY_SYNC_SERVER_HPP
