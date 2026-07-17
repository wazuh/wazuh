/* libcurl HTTPS transport engine — SPIKE #37738 PoC (C++17 core).
 * See hcClientFacade.hpp for the design notes. */

#include "hcClientFacade.hpp"
#include "hcCmac.hpp"

#include <strings.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <thread>
#include <vector>

namespace
{
    using CurlPtr = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
    using SlistPtr = std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)>;
    using FilePtr = std::unique_ptr<FILE, decltype(&fclose)>;

    /* curl callbacks are C: nothing may throw across them */
    size_t writeCb(char* ptr, size_t sz, size_t nm, void* ud)
    {
        auto* out = static_cast<std::string*>(ud);
        const size_t n = sz * nm;
        try
        {
            out->append(ptr, n);
        }
        catch (...)
        {
            return 0; /* abort the transfer */
        }
        return n;
    }

    /* capture Retry-After from response headers (back-pressure signal) */
    size_t headerCb(char* b, size_t sz, size_t nm, void* ud)
    {
        const size_t n = sz * nm;
        auto* retryAfter = static_cast<long*>(ud);
        if (n > 12 && strncasecmp(b, "Retry-After:", 12) == 0)
        {
            *retryAfter = strtol(b + 12, nullptr, 10);
        }
        return n;
    }

    size_t readFileCb(char* buf, size_t sz, size_t nm, void* ud)
    {
        return fread(buf, 1, sz * nm, static_cast<FILE*>(ud));
    }

    std::string orEmpty(const char* s)
    {
        return s ? std::string {s} : std::string {};
    }
} // namespace

HcClientFacade::HcClientFacade(const hc_config_t& cfg, const hc_callbacks_t& cb)
    : m_cb(cb)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    m_cfg.baseUrl = orEmpty(cfg.base_url);
    m_cfg.agentId = orEmpty(cfg.agent_id);
    m_cfg.agentKeyHex = orEmpty(cfg.agent_key_hex);
    m_cfg.verifyMode = cfg.verify_mode;
    m_cfg.caPath = orEmpty(cfg.ca_path);
    m_cfg.clientCert = orEmpty(cfg.client_cert);
    m_cfg.clientKey = orEmpty(cfg.client_key);
    m_cfg.batchSizeBytes = cfg.batch_size_bytes;
    m_cfg.batchIntervalMs = cfg.batch_interval_ms;
    m_cfg.version = orEmpty(cfg.version);
    m_cfg.configChecksum = orEmpty(cfg.config_checksum);
    m_cfg.backoffBaseMs = cfg.backoff_base_ms;
    m_cfg.backoffCapMs = cfg.backoff_cap_ms;
    m_cfg.requestTimeoutMs = cfg.request_timeout_ms;

    m_accCap = m_cfg.batchSizeBytes ? m_cfg.batchSizeBytes : (1u << 20);
    m_acc.reserve(m_accCap);
    m_accSince = std::chrono::steady_clock::now();
}

HcClientFacade::~HcClientFacade()
{
    setState(HC_STATE_STOPPED);
    curl_global_cleanup();
}

void HcClientFacade::setState(hc_conn_state_t s)
{
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        changed = (m_state != s);
        m_state = s;
    }
    if (changed && m_cb.on_state_change) /* callback outside the lock */
    {
        m_cb.on_state_change(s);
    }
}

hc_conn_state_t HcClientFacade::state() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_state;
}

void HcClientFacade::logf(int level, const char* fmt, ...)
{
    if (!m_cb.log)
    {
        return;
    }
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    m_cb.log(level, buf);
}

void HcClientFacade::applyTls(CURL* c) const
{
    switch (m_cfg.verifyMode)
    {
        case HC_VERIFY_NONE:
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
            break;
        case HC_VERIFY_CERT:
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
            break;
        case HC_VERIFY_FULL:
        default:
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
            break;
    }
    if (!m_cfg.caPath.empty())
    {
        curl_easy_setopt(c, CURLOPT_CAINFO, m_cfg.caPath.c_str());
    }
    if (!m_cfg.clientCert.empty())
    {
        curl_easy_setopt(c, CURLOPT_SSLCERT, m_cfg.clientCert.c_str());
    }
    if (!m_cfg.clientKey.empty())
    {
        curl_easy_setopt(c, CURLOPT_SSLKEY, m_cfg.clientKey.c_str());
    }
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L); /* H4: no redirects */
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);       /* H6 */
}

/* the two auth headers (+ optional session header) for one signed attempt;
 * called per attempt so every retry re-signs with a fresh timestamp */
curl_slist* HcClientFacade::buildHeaders(const std::string& method,
                                         const std::string& target,
                                         const uint8_t* body, size_t bodyLen,
                                         const std::string& sessionHeader) const
{
    const long ts = static_cast<long>(time(nullptr));
    const auto canonical =
        HcCmac::canonicalRequest(method, target, m_cfg.agentId, ts, body, bodyLen);
    const auto mac = HcCmac::macHex(m_cfg.agentKeyHex, canonical.data(), canonical.size());
    if (!mac)
    {
        return nullptr;
    }

    const std::string auth =
        "Authorization: Wazuh " + m_cfg.agentId + ":" + std::to_string(ts) + ":" + *mac;

    curl_slist* hl = nullptr;
    hl = curl_slist_append(hl, "protocol-version: 1");
    hl = curl_slist_append(hl, auth.c_str());
    if (!sessionHeader.empty())
    {
        hl = curl_slist_append(hl, sessionHeader.c_str());
    }
    hl = curl_slist_append(hl, "Content-Type: application/octet-stream");
    hl = curl_slist_append(hl, "Expect:"); /* avoid 100-continue */
    return hl;
}

/* classify an HTTP/transport outcome into the D9 error classes */
int HcClientFacade::classify(CURLcode cc, long http)
{
    if (cc != CURLE_OK)
    {
        return HC_RETRYABLE; /* timeout/DNS/TLS */
    }
    if (http >= 200 && http < 300)
    {
        return HC_OK;
    }
    if (http == 401)
    {
        return HC_AUTH_FAIL;
    }
    if (http == 503 || http == 429)
    {
        return HC_BACKPRESSURE;
    }
    if (http >= 500)
    {
        return HC_RETRYABLE;
    }
    return HC_PERMANENT; /* 400/413/... */
}

/* one signed POST from an in-memory body */
int HcClientFacade::postMem(const std::string& target, const uint8_t* body,
                            size_t len, Response& resp)
{
    const CurlPtr c {curl_easy_init(), curl_easy_cleanup};
    if (!c)
    {
        return HC_ERROR;
    }
    const std::string url = m_cfg.baseUrl + target;
    const SlistPtr hl {buildHeaders("POST", target, body, len, {}), curl_slist_free_all};
    if (!hl)
    {
        return HC_ERROR;
    }

    curl_easy_setopt(c.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(c.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(c.get(), CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(len));
    curl_easy_setopt(c.get(), CURLOPT_HTTPHEADER, hl.get());
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(c.get(), CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(c.get(), CURLOPT_HEADERFUNCTION, headerCb);
    curl_easy_setopt(c.get(), CURLOPT_HEADERDATA, &resp.retryAfter);
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(m_cfg.requestTimeoutMs));
    applyTls(c.get());

    const CURLcode cc = curl_easy_perform(c.get());
    curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &resp.http);
    if (cc != CURLE_OK)
    {
        logf(1, "transport error on %s: %s", target.c_str(), curl_easy_strerror(cc));
    }
    return classify(cc, resp.http);
}

/* streamed POST from a spooled file (the /stateful memory technique). We sign
 * the exact bytes we will stream (read the temp file once to compute the CMAC,
 * then rewind and let libcurl stream it). */
int HcClientFacade::postFile(const std::string& target, const std::string& path,
                             const std::string& sessionId, Response& resp)
{
    const FilePtr f {fopen(path.c_str(), "rb"), fclose};
    if (!f)
    {
        return HC_ERROR;
    }
    fseek(f.get(), 0, SEEK_END);
    const long fsz = ftell(f.get());
    fseek(f.get(), 0, SEEK_SET);

    std::vector<uint8_t> body(fsz > 0 ? static_cast<size_t>(fsz) : 0);
    if (!body.empty() && fread(body.data(), 1, body.size(), f.get()) != body.size())
    {
        return HC_ERROR;
    }
    rewind(f.get());

    const std::string sessionHeader = "X-Session-Id: " + sessionId;
    const SlistPtr hl {buildHeaders("POST", target, body.data(), body.size(), sessionHeader),
                       curl_slist_free_all};
    if (!hl)
    {
        return HC_ERROR;
    }

    const CurlPtr c {curl_easy_init(), curl_easy_cleanup};
    if (!c)
    {
        return HC_ERROR;
    }
    const std::string url = m_cfg.baseUrl + target;

    curl_easy_setopt(c.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(c.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(c.get(), CURLOPT_READFUNCTION, readFileCb); /* stream from file */
    curl_easy_setopt(c.get(), CURLOPT_READDATA, f.get());
    curl_easy_setopt(c.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(fsz));
    curl_easy_setopt(c.get(), CURLOPT_HTTPHEADER, hl.get());
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(c.get(), CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(c.get(), CURLOPT_HEADERFUNCTION, headerCb);
    curl_easy_setopt(c.get(), CURLOPT_HEADERDATA, &resp.retryAfter);
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(m_cfg.requestTimeoutMs));
    applyTls(c.get());

    const CURLcode cc = curl_easy_perform(c.get());
    curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &resp.http);
    return classify(cc, resp.http);
}

bool HcClientFacade::submitEvent(const uint8_t* frame, size_t len)
{
    /* becomes one "E <frame>\n" line; embedded newlines get a leading space
     * (H/E continuation escaping, #37732 OpenAPI). PoC keeps it simple.
     * Called from agentd's intake thread; guarded against the sender thread. */
    const size_t need = 2 + len + 1;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_acc.size() + need > m_accCap) /* D6 O-a: drop-newest */
        {
            /* log outside the lock, below */
        }
        else
        {
            m_acc.append("E ", 2);
            m_acc.append(reinterpret_cast<const char*>(frame), len);
            m_acc.push_back('\n');
            m_accEvents++;
            return true;
        }
    }
    logf(2, "stateless accumulator full (%zu B) -> drop-newest", m_accCap);
    return false;
}

int HcClientFacade::flushEvents()
{
    /* snapshot the accumulator under the lock, send unlocked (so intake never
     * blocks on the network), then consume only the sent prefix — anything
     * appended during the send survives (tail-preserving). */
    size_t take = 0;
    unsigned ev = 0;
    std::string body;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_acc.empty())
        {
            return HC_OK;
        }
        take = m_acc.size();
        ev = m_accEvents;
        body = "H {\"wazuh\":{\"agent\":{\"id\":\"" + m_cfg.agentId + "\"}}}\n";
        body.append(m_acc, 0, take);
    }

    Response resp;
    const int cls = postMem("/stateless",
                            reinterpret_cast<const uint8_t*>(body.data()),
                            body.size(), resp);
    logf(0, "/stateless -> HTTP %ld (%zu B, %u events)", resp.http, body.size(), ev);
    if (cls == HC_OK)
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_acc.erase(0, take); /* keep the tail */
        m_accEvents = (m_accEvents > ev) ? m_accEvents - ev : 0;
        m_backoffMs = 0;
    }
    return cls;
}

int HcClientFacade::submitSyncSession(const uint8_t* buf, size_t len,
                                      const std::string& sessionId,
                                      char** resultJsonOut)
{
    /* spool to a temp file to prove the streamed-body technique */
    char tmpl[] = "/tmp/hc_sync_XXXXXX";
    const int fd = mkstemp(tmpl);
    if (fd < 0)
    {
        return HC_ERROR;
    }
    {
        const FilePtr w {fdopen(fd, "wb"), fclose};
        if (!w || fwrite(buf, 1, len, w.get()) != len)
        {
            remove(tmpl);
            return HC_ERROR;
        }
    }

    Response resp;
    const int cls = postFile("/stateful", tmpl, sessionId, resp);
    logf(0, "/stateful session=%s -> HTTP %ld (%zu B streamed)",
         sessionId.c_str(), resp.http, len);
    remove(tmpl);

    if (cls == HC_OK && resultJsonOut)
    {
        /* boundary allocation: the C caller frees with free() */
        *resultJsonOut = resp.body.empty() ? nullptr : strdup(resp.body.c_str());
    }
    return cls;
}

int HcClientFacade::startup()
{
    const std::string body = "{\"phase\":\"startup\",\"version\":\"" + m_cfg.version +
                             "\",\"config_checksum\":\"" + m_cfg.configChecksum + "\"}";
    Response resp;
    const int cls = postMem("/control",
                            reinterpret_cast<const uint8_t*>(body.data()),
                            body.size(), resp);
    logf(0, "/control startup -> HTTP %ld", resp.http);
    const char* meta = resp.body.empty() ? nullptr : resp.body.c_str();
    if (cls == HC_OK)
    {
        setState(HC_STATE_REGISTERED);
        if (m_cb.on_startup_result)
        {
            m_cb.on_startup_result(true, meta);
        }
    }
    else if (resp.http == 426 || resp.http == 400)
    {
        setState(HC_STATE_REJECTED);
        if (m_cb.on_startup_result)
        {
            m_cb.on_startup_result(false, meta);
        }
    }
    else if (cls == HC_AUTH_FAIL)
    {
        setState(HC_STATE_AUTH_ERROR);
    }
    return cls;
}

int HcClientFacade::notify()
{
    const std::string body = "{\"phase\":\"notify\",\"status\":\"active\",\"merged_sum\":\"" +
                             m_cfg.configChecksum + "\"}";
    Response resp;
    const int cls = postMem("/control",
                            reinterpret_cast<const uint8_t*>(body.data()),
                            body.size(), resp);
    logf(0, "/control notify -> HTTP %ld", resp.http);
    if (cls == HC_OK && !resp.body.empty() && m_cb.on_task)
    {
        /* naive extraction of tasks[]: the PoC hands the whole body to the
         * dispatcher, which parses type/task_id (real code uses cJSON). */
        m_cb.on_task("_raw_notify_response", "", resp.body.c_str());
    }
    if (cls == HC_BACKPRESSURE)
    {
        logf(1, "back-pressure: Retry-After=%ld", resp.retryAfter);
        if (resp.retryAfter > 0)
        {
            std::this_thread::sleep_for(std::chrono::seconds(resp.retryAfter));
        }
    }
    return cls;
}
