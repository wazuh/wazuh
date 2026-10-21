/*
 * Wazuh content manager - public header guard
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 *
 * This translation unit exists to fail the build, and it is compiled with deliberately impoverished
 * include directories: only the module's own `include/` and nlohmann. Two regressions are caught here
 * and nowhere else.
 *
 *  1. **A C++20 construct in a public header.** The library is built as C++20, but the Engine's
 *     libraries are C++17 throughout. A `starts_with` or a `std::span` in `contentTypes.hpp` would
 *     compile inside the `.so` and break the Engine's build. This target is compiled as C++17.
 *
 *  2. **A private header leaking into `include/`.** `rocksDBWrapper.hpp` or `topicDriver.hpp`
 *     reached from a public header would drag rocksdb and the library's internals into every host.
 *     Their include directories are absent here, so such a leak stops compiling.
 */

#include "contentExport.hpp"
#include "contentIndexer.hpp"
#include "contentIndexerAdapters.hpp"
#include "contentLogging.hpp"
#include "contentRegister.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTopicSpec.hpp"
#include "contentTypes.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace
{

    using namespace content_manager;

    // Everything the sink promises is noexcept. This is the cross-DSO mitigation: an exception thrown
    // in a host's sink and caught inside the library would rely on RTTI unification across two
    // libstdc++ copies, which nothing guarantees.
    static_assert(noexcept(std::declval<IContentSink&>().beginSession(std::declval<const SessionInfo&>())),
                  "IContentSink::beginSession must be noexcept");
    static_assert(noexcept(std::declval<IContentSink&>().acceptPage(std::declval<const ContentPage&>())),
                  "IContentSink::acceptPage must be noexcept");
    static_assert(noexcept(std::declval<IContentSink&>().commit(std::declval<const CommitInfo&>())),
                  "IContentSink::commit must be noexcept");
    static_assert(noexcept(std::declval<IContentSink&>().abort(std::declval<AbortReason>(),
                                                               std::declval<const std::string&>())),
                  "IContentSink::abort must be noexcept");
    static_assert(noexcept(std::declval<IContentSink&>().cycleFinished(std::declval<const CycleOutcome&>())),
                  "IContentSink::cycleFinished must be noexcept");
    static_assert(noexcept(std::declval<IContentTokenStore&>().load(std::declval<std::string_view>())),
                  "IContentTokenStore::load must be noexcept");
    static_assert(noexcept(std::declval<IContentTokenStore&>().store(std::declval<std::string_view>(),
                                                                     std::declval<std::string_view>())),
                  "IContentTokenStore::store must be noexcept");
    static_assert(noexcept(std::declval<IContentIndexer&>().closePit(std::declval<const ContentPit&>())),
                  "IContentIndexer::closePit must be noexcept");
    static_assert(noexcept(std::declval<ContentRegister&>().runOnce(std::declval<RunRequest>())),
                  "ContentRegister::runOnce must be noexcept");
    static_assert(noexcept(std::declval<ContentRegister&>().requestRun(
                      std::declval<RunRequest>(), std::declval<std::function<void(OnDemandResult)>>())),
                  "ContentRegister::requestRun must be noexcept");
    static_assert(noexcept(std::declval<ContentRegister&>().currentToken()),
                  "ContentRegister::currentToken must be noexcept");

} // namespace
