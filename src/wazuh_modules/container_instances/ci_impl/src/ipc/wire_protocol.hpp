#pragma once

#include "query_types.hpp"

#include "json.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace wazuh::container_instances::wire
{

    inline constexpr int PROTOCOL_VERSION = 1;

    [[nodiscard]] inline std::string verdictReasonToString(VerdictReason reason)
    {
        switch (reason)
        {
            case VerdictReason::hostProcess: return "host_process";
            case VerdictReason::hostNamespace: return "host_namespace";
            case VerdictReason::cgroupnsHost: return "cgroupns_host";
            case VerdictReason::kata: return "kata";
        }
        return "host_process";
    }

    [[nodiscard]] inline std::string errorCodeToString(QueryResponse::ErrorCode code)
    {
        switch (code)
        {
            case QueryResponse::ErrorCode::badRequest: return "bad_request";
            case QueryResponse::ErrorCode::unsupportedVersion: return "unsupported_version";
            case QueryResponse::ErrorCode::internal: return "internal";
        }
        return "internal";
    }

    namespace detail
    {

        [[nodiscard]] inline QueryResponse makeError(QueryResponse::ErrorCode code, std::string message)
        {
            QueryResponse response;
            response.status = QueryResponse::Status::error;
            response.errorCode = code;
            response.errorMessage = std::move(message);
            return response;
        }

        /// cgroup_id travels as a decimal string: st_ino is 64-bit and cJSON-based
        /// consumers parse JSON numbers as double (silent corruption above 2^53).
        /// Every 64-bit value on this protocol travels as a decimal STRING,
        /// because cJSON — which some clients use — parses JSON numbers as
        /// doubles and silently rounds above 2^53. Applies to cgroup inodes and
        /// to the journal's epoch and sequence alike.
        [[nodiscard]] inline std::optional<std::uint64_t> parseDecimalU64(const nlohmann::json& value)
        {
            if (!value.is_string())
            {
                return std::nullopt;
            }
            const auto& text = value.get_ref<const std::string&>();
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
            {
                return std::nullopt;
            }
            try
            {
                return std::stoull(text);
            }
            catch (const std::exception&)
            {
                return std::nullopt;
            }
        }

    } // namespace detail

    /// One request line -> domain request, or an error response ready to send.
    /// Never throws: garbage in, error envelope out.
    [[nodiscard]] inline std::variant<QueryRequest, QueryResponse> parseRequest(std::string_view line)
    {
        const auto parsed = nlohmann::json::parse(line, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "malformed JSON");
        }

        if (!parsed.contains("version") || !parsed["version"].is_number_integer() ||
            parsed["version"].get<int>() != PROTOCOL_VERSION)
        {
            return detail::makeError(QueryResponse::ErrorCode::unsupportedVersion,
                                     "missing or unsupported protocol version");
        }

        QueryRequest request;
        request.version = PROTOCOL_VERSION;

        if (parsed.contains("op") && !parsed["op"].is_string())
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "unknown op");
        }
        const auto op = parsed.value("op", "");
        if (op == "status")
        {
            request.op = QueryRequest::Op::status;
            return request;
        }
        if (op == "list")
        {
            request.op = QueryRequest::Op::list;

            // Additive, and silently ignored by a server that predates it —
            // which is the whole reason the delta rides `list` rather than
            // arriving as a new op. An old server answers with the full set and
            // no epoch, and the client takes that as "deltas unavailable here"
            // without an error path on either side.
            //
            // Both halves must be present and well-formed to count: a cursor
            // with one half missing is a client bug, and serving it as "read
            // from the start" would quietly hand back a full set forever.
            if (parsed.contains("since_epoch") && parsed.contains("since_seq"))
            {
                const auto epoch = detail::parseDecimalU64(parsed["since_epoch"]);
                const auto seq = detail::parseDecimalU64(parsed["since_seq"]);

                if (!epoch || !seq)
                {
                    return detail::makeError(QueryResponse::ErrorCode::badRequest,
                                             "since_epoch and since_seq must be decimal strings");
                }
                request.since = LifecycleCursor {*epoch, *seq};
            }

            return request;
        }
        if (op != "resolve")
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "unknown op");
        }

        request.op = QueryRequest::Op::resolve;
        if (!parsed.contains("cgroup_id"))
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "cgroup_id missing");
        }
        const auto cgroupId = detail::parseDecimalU64(parsed["cgroup_id"]);
        if (!cgroupId)
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "cgroup_id must be a decimal string");
        }
        request.cgroupId = *cgroupId;

        if (parsed.contains("container_id") && parsed["container_id"].is_string())
        {
            request.containerId = parsed["container_id"].get<std::string>();
        }
        if (parsed.contains("pod_uid") && parsed["pod_uid"].is_string())
        {
            request.podUid = parsed["pod_uid"].get<std::string>();
        }
        if (parsed.contains("container_name") && parsed["container_name"].is_string())
        {
            request.containerName = parsed["container_name"].get<std::string>();
        }

        return request;
    }

    /// Docker records omit the Kubernetes-only keys entirely (absent, not null).
    [[nodiscard]] inline nlohmann::json recordToJson(const ContainerRecord& record)
    {
        nlohmann::json data;
        data["runtime"] = (record.runtime == ContainerRuntime::kubernetes) ? "kubernetes" : "docker";
        data["container_id"] = record.containerId;
        data["container_name"] = record.containerName;
        data["image"] = record.image;
        data["image_digest"] = record.imageDigest;
        data["restart_count"] = record.restartCount;

        // Additive, and omitted when the runtime did not report them rather
        // than sent empty: an absent key is how every optional field on this
        // protocol already reads, and a consumer that knows neither is
        // unaffected either way.
        if (!record.startedAt.empty())
        {
            data["started_at"] = record.startedAt;
        }
        if (record.pid != 0)
        {
            data["pid"] = record.pid;
        }
        data["node_name"] = record.nodeName;
        data["labels"] = record.labels;
        data["cgroup_id"] = std::to_string(record.cgroupId);

        if (record.runtime == ContainerRuntime::kubernetes)
        {
            data["pod_uid"] = record.podUid;
            data["pod_name"] = record.podName;
            data["namespace"] = record.podNamespace;
            data["annotations"] = record.annotations;
            auto owners = nlohmann::json::array();
            for (const auto& owner : record.ownerRefs)
            {
                owners.push_back({{"kind", owner.kind}, {"name", owner.name}, {"uid", owner.uid}});
            }
            data["owner_refs"] = std::move(owners);
        }

        auto network = nlohmann::json::array();
        for (const auto& iface : record.network)
        {
            network.push_back({{"name", iface.name}, {"ip", iface.ip}});
        }
        data["network"] = std::move(network);

        auto mounts = nlohmann::json::array();
        for (const auto& mount : record.ociMounts)
        {
            mounts.push_back({{"source", mount.source}, {"destination", mount.destination}, {"ro", mount.readOnly}});
        }
        data["oci_mounts"] = std::move(mounts);

        return data;
    }

    /// Names rather than a bitmask integer, because a consumer that meets a
    /// class it does not know must be able to see that it did. An unrecognised
    /// NAME is visibly unrecognised; an unrecognised BIT in an integer silently
    /// reads as zero, and a consumer would skip the re-scan it owed.
    [[nodiscard]] inline nlohmann::json changeMaskToNames(unsigned int mask)
    {
        auto names = nlohmann::json::array();

        if ((mask & LIFECYCLE_IDENTITY) != 0) names.push_back("identity");
        if ((mask & LIFECYCLE_IMAGE) != 0) names.push_back("image");
        if ((mask & LIFECYCLE_MOUNTS) != 0) names.push_back("mounts");
        if ((mask & LIFECYCLE_NETWORK) != 0) names.push_back("network");
        if ((mask & LIFECYCLE_METADATA) != 0) names.push_back("metadata");

        return names;
    }

    [[nodiscard]] inline const char* lifecycleKindToString(LifecycleKind kind)
    {
        switch (kind)
        {
            case LifecycleKind::added: return "added";
            case LifecycleKind::changed: return "changed";
            case LifecycleKind::removed: return "removed";
        }
        return "changed";
    }

    /// Adds the delta keys to a `list` reply. Everything here is additive: a
    /// client that does not know these keys reads the reply exactly as before.
    inline void serialiseDelta(const LifecycleDelta& delta, nlohmann::json& body)
    {
        // The cursor to come back with. Decimal strings for the 2^53 reason
        // above; its presence is also how a client detects that this server
        // supports deltas at all.
        body["epoch"] = std::to_string(delta.cursor.epoch);
        body["seq"] = std::to_string(delta.cursor.seq);

        if (delta.resyncRequired)
        {
            // The full set already rode along in `containers`. Saying so
            // explicitly rather than letting the client infer it from an empty
            // event list, which is also what "nothing changed" looks like.
            body["resync_required"] = true;
            return;
        }

        auto events = nlohmann::json::array();

        for (const auto& event : delta.events)
        {
            nlohmann::json entry;
            entry["seq"] = std::to_string(event.seq);
            entry["kind"] = lifecycleKindToString(event.kind);
            entry["container_id"] = event.containerId;
            // Carried on every kind, removals included: a consumer keyed on the
            // cgroup inode cannot act on a removal it cannot map back to one.
            entry["cgroup_id"] = std::to_string(event.cgroupId);

            if (event.kind == LifecycleKind::changed)
            {
                entry["changed"] = changeMaskToNames(event.changed);
            }
            if (event.record)
            {
                entry["data"] = recordToJson(*event.record);
            }

            events.push_back(std::move(entry));
        }

        body["events"] = std::move(events);
    }

    [[nodiscard]] inline std::string serializeResponse(const QueryResponse& response)
    {
        nlohmann::json body;
        body["version"] = PROTOCOL_VERSION;

        switch (response.status)
        {
            case QueryResponse::Status::resolved:
                body["status"] = "resolved";
                body["data"] = response.record ? recordToJson(*response.record) : nlohmann::json::object();
                break;
            case QueryResponse::Status::pending:
                body["status"] = "pending";
                body["retry_after_ms"] = response.retryAfterMs;
                break;
            case QueryResponse::Status::notContainer:
                body["status"] = "not_container";
                body["reason"] = verdictReasonToString(response.reason.value_or(VerdictReason::hostProcess));
                break;
            case QueryResponse::Status::ok:
            {
                body["status"] = "ok";
                nlohmann::json data;
                if (response.stats)
                {
                    data["records"] = response.stats->resolved;
                    data["pending"] = response.stats->pending;
                    data["verdicts"] = response.stats->verdicts;
                }
                data["connector"] = response.connectorName;
                body["data"] = std::move(data);

                // Unconditional for a `list` reply, empty array included. A
                // client cannot distinguish "no containers" from "no connector"
                // on a key that is absent, so omitting it made every
                // container-free host look like a dead connector: both consumers
                // then suppressed their stale-row sweep (correctly, given what
                // they were told) and logged a fault that was not occurring.
                // C28. Not emitted for a `status` reply, which shares this
                // branch but says nothing about the container set.
                if (response.listReply)
                {
                    auto containers = nlohmann::json::array();
                    for (const auto& record : response.containers)
                    {
                        if (record)
                        {
                            containers.push_back(recordToJson(*record));
                        }
                    }
                    body["containers"] = std::move(containers);
                }

                if (response.delta)
                {
                    serialiseDelta(*response.delta, body);
                }
                break;
            }
            case QueryResponse::Status::error:
                body["status"] = "error";
                body["error"] = {
                    {"code", errorCodeToString(response.errorCode.value_or(QueryResponse::ErrorCode::internal))},
                    {"message", response.errorMessage}};
                break;
        }

        return body.dump();
    }

} // namespace wazuh::container_instances::wire
