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
        [[nodiscard]] inline std::optional<std::uint64_t> parseCgroupId(const nlohmann::json& value)
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
        if (op != "resolve")
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "unknown op");
        }

        request.op = QueryRequest::Op::resolve;
        if (!parsed.contains("cgroup_id"))
        {
            return detail::makeError(QueryResponse::ErrorCode::badRequest, "cgroup_id missing");
        }
        const auto cgroupId = detail::parseCgroupId(parsed["cgroup_id"]);
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
