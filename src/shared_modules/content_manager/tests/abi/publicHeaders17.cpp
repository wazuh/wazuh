/*
 * Wazuh content manager - public ABI guard
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * This translation unit exists to fail the build, and it is compiled with deliberately impoverished
 * include directories: only the module's own `include/`, nlohmann and `shared_modules/utils`. Two
 * regressions are caught here and nowhere else.
 *
 *  1. **A C++20 construct in a public header.** The library is built as C++20, but its hosts are
 *     not: the Engine's libraries are C++17 throughout. A `starts_with` or a `std::span` in
 *     `contentTypes.hpp` would compile perfectly inside the `.so` and break the Engine's build.
 *     This target is compiled with `CXX_STANDARD 17`.
 *
 *  2. **A private header leaking into `include/`.** `rocksDBWrapper.hpp`, `contentModuleFacade.hpp`
 *     and `onDemandManager.hpp` are implementation detail; a public header that reached for one
 *     would drag rocksdb, or a second copy of a singleton, into every host. Their include
 *     directories are absent here, so such a leak stops compiling.
 *
 * The assertions below additionally pin the layout of every struct the contract passes across the
 * DSO boundary. Each is checked against a mirror declared with the same members in the same order,
 * so adding, removing or reordering a field fails here — and, unlike hand-computed byte counts, the
 * check stays correct on any ABI. They are not a substitute for `CONTRACT_ABI_VERSION`; they are
 * what makes it impossible to change a layout without noticing that the version must move too.
 */

#include "contentManager.hpp"
#include "contentOnDemand.hpp"
#include "contentRegister.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include "sharedDefs.hpp"

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace content_manager;

static_assert(CONTRACT_ABI_VERSION == 2, "Bumping the contract version requires updating this guard.");

// Enumerators are pinned to one byte: a host and the library must agree on the size of every member
// of the aggregates below, and an unpinned enum's underlying type is the compiler's choice.
static_assert(sizeof(SessionKind) == 1, "SessionKind must stay a one-byte enum");
static_assert(sizeof(SessionDecision) == 1, "SessionDecision must stay a one-byte enum");
static_assert(sizeof(PageStatus) == 1, "PageStatus must stay a one-byte enum");
static_assert(sizeof(CommitStatus) == 1, "CommitStatus must stay a one-byte enum");
static_assert(sizeof(AbortReason) == 1, "AbortReason must stay a one-byte enum");
static_assert(sizeof(CycleStatus) == 1, "CycleStatus must stay a one-byte enum");
static_assert(sizeof(OnDemandCode) == 1, "OnDemandCode must stay a one-byte enum");

struct SessionInfoMirror
{
    std::string topic;
    SessionKind kind;
    std::string localToken;
    std::string remoteToken;
    nlohmann::json probeMetadata;
    bool onDemand;
};

struct ContentPageMirror
{
    std::string_view topic;
    const nlohmann::json* hits;
    std::string pageToken;
    std::size_t sliceId;
    std::size_t pageIndex;
};

struct PageAckMirror
{
    PageStatus status;
    std::string detail;
};

struct CommitInfoMirror
{
    std::string topic;
    SessionKind kind;
    std::string finalToken;
    std::size_t documentsDelivered;
    bool changed;
};

struct CommitResultMirror
{
    CommitStatus status;
    std::string detail;
};

struct CycleOutcomeMirror
{
    CycleStatus status;
    std::size_t documentsDelivered;
    std::string token;
    std::string detail;
    std::chrono::seconds retryAfter;
};

struct RunRequestMirror
{
    bool forceFullReload;
    bool onDemand;
};

struct OnDemandResultMirror
{
    OnDemandCode code;
    std::string detail;
};

#define ASSERT_LAYOUT(type)                                                                                            \
    static_assert(sizeof(type) == sizeof(type##Mirror), #type " layout changed: bump CONTRACT_ABI_VERSION");           \
    static_assert(alignof(type) == alignof(type##Mirror), #type " alignment changed: bump CONTRACT_ABI_VERSION")

ASSERT_LAYOUT(SessionInfo);
ASSERT_LAYOUT(ContentPage);
ASSERT_LAYOUT(PageAck);
ASSERT_LAYOUT(CommitInfo);
ASSERT_LAYOUT(CommitResult);
ASSERT_LAYOUT(CycleOutcome);
ASSERT_LAYOUT(RunRequest);
ASSERT_LAYOUT(OnDemandResult);

#undef ASSERT_LAYOUT

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
static_assert(noexcept(std::declval<IContentTokenStore&>().load(std::declval<std::string_view>())),
              "IContentTokenStore::load must be noexcept");
static_assert(noexcept(std::declval<IContentTokenStore&>().store(std::declval<std::string_view>(),
                                                                 std::declval<std::string_view>())),
              "IContentTokenStore::store must be noexcept");
static_assert(noexcept(std::declval<ContentRegister&>().runOnce(std::declval<RunRequest>())),
              "ContentRegister::runOnce must be noexcept");
static_assert(noexcept(std::declval<ContentRegister&>().currentToken()),
              "ContentRegister::currentToken must be noexcept");

} // namespace
