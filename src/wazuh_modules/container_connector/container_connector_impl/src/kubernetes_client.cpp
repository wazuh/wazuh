#include "kubernetes_client.hpp"

#include "HTTPRequest.hpp"
#include "logging_helper.h"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace wazuh::container_connector {

namespace {

constexpr const char* kDefaultCaBundle  = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
constexpr const char* kDefaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

std::string EnvOrEmpty(const char* name)
{
    const char* v = std::getenv(name);
    return (v && *v) ? std::string{v} : std::string{};
}

std::string ReadWholeFileTrimmed(const std::string& path)
{
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error{"Failed to open file: " + path};
    }
    std::stringstream ss;
    ss << f.rdbuf();
    auto content = ss.str();
    while (!content.empty() && std::isspace(static_cast<unsigned char>(content.back()))) {
        content.pop_back();
    }
    return content;
}

} // namespace

KubernetesClient::KubernetesClient(KubernetesConfig                config,
                                   std::shared_ptr<StopController> stop,
                                   LogCallback                     log)
    : config_(std::move(config))
    , stop_(std::move(stop))
    , log_(std::move(log))
{
    // Config resolution is deferred to the first request so a transient absence
    // of in-cluster env vars (e.g. agent starts before the DaemonSet env is fully
    // populated) does not abort module startup. PodWatcher absorbs the failure
    // through its backoff loop.
}

void KubernetesClient::Log(int level, const std::string& msg) const
{
    if (log_) {
        log_(level, msg);
    }
}

void KubernetesClient::ResolveEffectiveConfig()
{
    effective_ca_bundle_  = config_.ca_bundle.empty()  ? std::string{kDefaultCaBundle}  : config_.ca_bundle;
    effective_token_path_ = config_.token_path.empty() ? std::string{kDefaultTokenPath} : config_.token_path;

    if (!config_.api_server.empty()) {
        effective_api_server_ = config_.api_server;
    } else {
        const auto host = EnvOrEmpty("KUBERNETES_SERVICE_HOST");
        if (host.empty()) {
            throw std::runtime_error{
                "Cannot resolve Kubernetes API server: api_server not configured and "
                "$KUBERNETES_SERVICE_HOST is empty (is the agent running in-cluster?)."};
        }
        const auto port = EnvOrEmpty("KUBERNETES_SERVICE_PORT");
        effective_api_server_ = std::string{"https://"} + host + (port.empty() ? "" : (":" + port));
    }

    if (!config_.node_name.empty()) {
        effective_node_name_ = config_.node_name;
    } else {
        const auto env = EnvOrEmpty("NODE_NAME");
        if (env.empty()) {
            throw std::runtime_error{
                "Cannot resolve node name: <node_name> not configured and $NODE_NAME is empty. "
                "Set the env var on the DaemonSet via fieldRef spec.nodeName."};
        }
        effective_node_name_ = env;
    }

    // Promote to INFO the first time we successfully resolve, so an operator
    // sees the working endpoint exactly once. Subsequent re-resolutions stay
    // at DEBUG to avoid log spam.
    const auto level = resolution_logged_ ? LOG_DEBUG : LOG_INFO;
    Log(level, "K8s client config resolved: api_server='" + effective_api_server_ +
                   "', ca_bundle='" + effective_ca_bundle_ +
                   "', token_path='" + effective_token_path_ +
                   "', node_name='" + effective_node_name_ + "'.");
    resolution_logged_ = true;
}

std::string KubernetesClient::ReadBearerToken() const
{
    // Re-read on every call so projected service-account token rotations are picked up
    // without a module restart.
    auto token = ReadWholeFileTrimmed(effective_token_path_);
    if (token.empty()) {
        throw std::runtime_error{"Empty bearer token in " + effective_token_path_};
    }
    return token;
}

namespace {

/// Strips the CRI runtime prefix from a container ID:
///   "containerd://abc123..." -> "abc123..."
///   "docker://abc123..."     -> "abc123..."
/// Returns the input unchanged if no recognised prefix is present.
std::string StripRuntimePrefix(const std::string& cri_id)
{
    const auto sep = cri_id.find("://");
    if (sep == std::string::npos) return cri_id;
    return cri_id.substr(sep + 3);
}

void ParseStringMap(const nlohmann::json& src, std::map<std::string, std::string>& dst)
{
    if (!src.is_object()) return;
    for (auto it = src.begin(); it != src.end(); ++it) {
        if (it.value().is_string()) {
            dst.emplace(it.key(), it.value().get<std::string>());
        }
    }
}

} // namespace

std::vector<PodSnapshot> KubernetesClient::ListPodsOnNode()
{
    if (stop_->IsStopRequested()) {
        return {};
    }

    // Re-resolve every call so the watcher's backoff loop can recover from a
    // transient absence of env vars or a config change without a restart.
    ResolveEffectiveConfig();

    const auto token = ReadBearerToken();

    HttpURL url(effective_api_server_ +
                "/api/v1/pods?fieldSelector=spec.nodeName=" + effective_node_name_);

    auto secure = SecureCommunication::builder().caRootCertificate(effective_ca_bundle_);

    const std::unordered_set<std::string> headers {
        "Accept: application/json",
        "Authorization: Bearer " + token,
    };

    std::string body;
    long        status        = 0;
    std::string error_message;

    HTTPRequest::instance().get(
        TRequestParameters<std::string> {
            .url                 = url,
            .secureCommunication = secure,
            .httpHeaders         = headers,
        },
        TPostRequestParameters<const std::string&> {
            .onSuccess = [&](const std::string& response) {
                body   = response;
                status = 200;
            },
            .onError   = [&](const std::string& err, const long code, const std::string&) {
                status        = code;
                error_message = err;
            },
        },
        ConfigurationParameters {
            .timeout = 5000,
        });

    if (stop_->IsStopRequested()) {
        return {};
    }

    if (status != 200) {
        throw std::runtime_error{"GET /api/v1/pods failed: status=" + std::to_string(status) +
                                 " message='" + error_message + "'"};
    }

    nlohmann::json doc = nlohmann::json::parse(body, /*cb*/ nullptr, /*throw*/ false);
    if (doc.is_discarded() || !doc.is_object() || !doc.contains("items") || !doc["items"].is_array()) {
        throw std::runtime_error{"GET /api/v1/pods returned invalid JSON or missing 'items' array."};
    }

    std::vector<PodSnapshot> snapshots;
    snapshots.reserve(doc["items"].size());

    for (const auto& item : doc["items"]) {
        if (!item.is_object()) continue;

        auto pod = std::make_shared<PodInfo>();

        if (auto md_it = item.find("metadata"); md_it != item.end() && md_it->is_object()) {
            const auto& md = *md_it;
            if (auto v = md.find("uid");       v != md.end() && v->is_string()) pod->pod_uid     = v->get<std::string>();
            if (auto v = md.find("name");      v != md.end() && v->is_string()) pod->pod_name    = v->get<std::string>();
            if (auto v = md.find("namespace"); v != md.end() && v->is_string()) pod->namespace_  = v->get<std::string>();
            if (auto v = md.find("labels");      v != md.end()) ParseStringMap(*v, pod->labels);
            if (auto v = md.find("annotations"); v != md.end()) ParseStringMap(*v, pod->annotations);
            if (auto v = md.find("ownerReferences"); v != md.end() && v->is_array()) {
                for (const auto& or_item : *v) {
                    if (!or_item.is_object()) continue;
                    OwnerRef ref;
                    if (auto k = or_item.find("kind"); k != or_item.end() && k->is_string()) ref.kind = k->get<std::string>();
                    if (auto n = or_item.find("name"); n != or_item.end() && n->is_string()) ref.name = n->get<std::string>();
                    if (!ref.kind.empty() || !ref.name.empty()) pod->owner_refs.push_back(std::move(ref));
                }
            }
        }

        if (auto spec_it = item.find("spec"); spec_it != item.end() && spec_it->is_object()) {
            if (auto v = spec_it->find("nodeName"); v != spec_it->end() && v->is_string()) {
                pod->node_name = v->get<std::string>();
            }
        }

        PodSnapshot snap;
        snap.pod = pod;

        if (auto st_it = item.find("status"); st_it != item.end() && st_it->is_object()) {
            if (auto cs_it = st_it->find("containerStatuses");
                cs_it != st_it->end() && cs_it->is_array()) {
                for (const auto& cs : *cs_it) {
                    if (!cs.is_object()) continue;
                    ContainerInPod c;
                    if (auto v = cs.find("name");         v != cs.end() && v->is_string())  c.name         = v->get<std::string>();
                    if (auto v = cs.find("image");        v != cs.end() && v->is_string())  c.image        = v->get<std::string>();
                    if (auto v = cs.find("imageID");      v != cs.end() && v->is_string())  c.image_id     = v->get<std::string>();
                    if (auto v = cs.find("restartCount"); v != cs.end() && v->is_number_integer()) c.restart_count = v->get<int>();
                    if (auto v = cs.find("containerID");  v != cs.end() && v->is_string())  c.container_id = StripRuntimePrefix(v->get<std::string>());
                    // c.pod and c.cgroup_id are populated by MetadataCache::Reconcile and T-K5 respectively.
                    snap.containers.push_back(std::move(c));
                }
            }
        }

        snapshots.push_back(std::move(snap));
    }

    Log(LOG_DEBUG, "K8s pod list: " + std::to_string(snapshots.size()) +
                   " pod(s) on node '" + effective_node_name_ + "'.");

    return snapshots;
}

} // namespace wazuh::container_connector
