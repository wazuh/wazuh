/*
 * Wazuh authd - enrollment token mint validation
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Everything that decides whether a token CAN be minted, kept out of the store so that the store
 * only ever deals with requests that are already known to be usable.
 *
 * The rule that shapes this file: a token is a promise to an agent that has nothing else to go on.
 * It names one endpoint and one trust anchor, and an agent that cannot reach that endpoint or
 * cannot match that anchor has no fallback and no way to be told why -- it simply fails to enroll,
 * in the field, after the operator has already distributed the token. So every check that can be
 * made at mint time is made here, against the listener certificate as it is on disk right now:
 *
 *   - the address must be a subject alternative name of the listener certificate, or TLS
 *     verification on the agent side will fail no matter how correct the rest of the token is;
 *   - a certificate that only names loopback cannot be reached by any agent at all;
 *   - the CA must actually sign that certificate, or the pin the token carries pins nothing.
 *
 * The refusals therefore carry a `detail` the operator can act on ("address not in certificate
 * SAN"), which the local server hands back verbatim: "invalid request" would send them looking in
 * the wrong place.
 */

#include <shared.h>

#include "enrollment_token_mint.h"
#include "enrollment_token_store.h"
#include "enrollment_token.h"
#include "mconf-config.h"
#include "x509_op.h"

/* Defaults of the `remote.https` section, mirrored from the manager schema. Read as fallbacks only:
 * w_mconf_section() serves the effective document, so an absent item means the schema itself
 * changed, and refusing to mint over that would be worse than minting for the documented default */
#define ETOKEN_DEFAULT_HTTPS_PORT   1517
#define ETOKEN_DEFAULT_HTTPS_PREFIX "/wazuh-manager/"
#define ETOKEN_DEFAULT_CERTIFICATE  "etc/certs/remoted.pem"
#define ETOKEN_DEFAULT_CA           "etc/certs/root-ca.pem"

/* Ceiling for an embedded CA. A CA certificate is a couple of kilobytes; this only exists so a
 * mistyped path pointing at something huge is refused instead of copied into every token */
#define ETOKEN_CA_MAX_BYTES (64 * 1024)

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

/**
 * @brief Write the reason of a refusal, if the caller asked for one.
 */
static void etoken_detail(char *detail, size_t detail_size, const char *fmt, ...) {
    va_list args;

    if (detail == NULL || detail_size == 0) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(detail, detail_size, fmt, args);
    va_end(args);
}

/**
 * @brief One integer item of the `https` object, or @p def when it is absent or of another type.
 */
static long etoken_conf_int(const cJSON *https, const char *name, long def) {
    const cJSON *item = cJSON_GetObjectItem((cJSON *) https, name);

    return cJSON_IsNumber((cJSON *) item) ? (long) item->valuedouble : def;
}

/**
 * @brief One string item of the `https` object, or @p def. Always a newly allocated copy.
 */
static char *etoken_conf_string(const cJSON *https, const char *name, const char *def) {
    const cJSON *item = cJSON_GetObjectItem((cJSON *) https, name);
    const char *value = (cJSON_IsString((cJSON *) item) && item->valuestring[0] != '\0')
                            ? item->valuestring
                            : def;
    char *copy = NULL;

    if (value != NULL) {
        os_strdup(value, copy);
    }

    return copy;
}

/**
 * @brief Build the `adr` field of a token: `host[:port][/[prefix]]`.
 *
 * Only what an agent cannot infer is written. The default port and the default prefix are dropped
 * -- an agent applies them itself, and every byte of a token is copied by hand somewhere -- while a
 * manager that serves NO prefix has to be stated explicitly ("host/"), because the absence of a
 * prefix is not the same answer as "use the default one".
 *
 * @param address Host: DNS name or IP literal (an IPv6 literal is bracketed here).
 * @param port Effective port.
 * @param prefix Effective prefix as configured or requested, with or without its slashes; NULL is
 *               read as the default prefix.
 * @return Newly allocated endpoint the caller must free(), or NULL on error.
 */
static char *etoken_adr_build(const char *address, long port, const char *prefix) {
    char *adr = NULL;
    char *trimmed = NULL;
    size_t len;
    size_t start = 0;
    size_t end;
    size_t size;

    if (address == NULL || address[0] == '\0') {
        return NULL;
    }

    /* The prefix as a bare path with no slashes around it: "/wazuh-manager/" and "wazuh-manager"
     * are the same prefix written two ways, and "/" is the same as "" -- no prefix at all */
    if (prefix == NULL) {
        os_strdup(W_ETOKEN_DEFAULT_PREFIX, trimmed);
    } else {
        len = strlen(prefix);
        end = len;

        while (start < end && prefix[start] == '/') {
            start++;
        }

        while (end > start && prefix[end - 1] == '/') {
            end--;
        }

        os_calloc(end - start + 1, sizeof(char), trimmed);
        memcpy(trimmed, prefix + start, end - start);
    }

    /* Host, an IPv6 literal between brackets so that the ':' of the port stays unambiguous */
    size = strlen(address) + strlen(trimmed) + 32;
    os_calloc(size, sizeof(char), adr);

    if (strchr(address, ':') != NULL) {
        snprintf(adr, size, "[%s]", address);
    } else {
        snprintf(adr, size, "%s", address);
    }

    if (port != W_ETOKEN_DEFAULT_PORT) {
        len = strlen(adr);
        snprintf(adr + len, size - len, ":%ld", port);
    }

    if (trimmed[0] == '\0') {
        /* Explicit "no prefix": the routes are served at the root of the host */
        len = strlen(adr);
        snprintf(adr + len, size - len, "/");
    } else if (strcmp(trimmed, W_ETOKEN_DEFAULT_PREFIX) != 0) {
        len = strlen(adr);
        snprintf(adr + len, size - len, "/%s", trimmed);
    }

    os_free(trimmed);

    return adr;
}

/**
 * @brief Whether the endpoint is accepted by the token grammar.
 *
 * w_etoken_encode() is the authority on that grammar, so it is asked here rather than reimplemented
 * -- with a throwaway token, purely so that a rejection surfaces as a refusal with a reason instead
 * of an unexplained failure two functions later, once the store has already drawn a secret.
 */
static int etoken_adr_is_encodable(const char *adr) {
    w_etoken_t probe;
    char *text = NULL;
    int encodable;

    memset(&probe, 0, sizeof(probe));
    probe.ver = 1;
    probe.adr = (char *) adr;
    probe.has_pin = 1;

    text = w_etoken_encode(&probe);
    encodable = (text != NULL);
    os_free(text);

    return encodable;
}

int etoken_mint_prepare(const etoken_mint_request_t *req, etoken_mint_t *out, char *detail, size_t detail_size) {
    cJSON *remote = NULL;
    const cJSON *https = NULL;
    X509 *leaf = NULL;
    X509 *ca = NULL;
    ASN1_OCTET_STRING *literal = NULL;
    char *certificate = NULL;
    char *ca_certificate = NULL;
    char *prefix = NULL;
    long conf_port;
    long port;
    int ret = -2;

    if (req == NULL || out == NULL) {
        etoken_detail(detail, detail_size, "internal error: no request");
        return -2;
    }

    memset(out, 0, sizeof(*out));

    if (req->address == NULL || req->address[0] == '\0') {
        etoken_detail(detail, detail_size, "address is required");
        return -1;
    }

    /* The running listener's own configuration: the token has to describe THAT, not what the
     * operator remembers having configured */
    if (remote = w_mconf_section("remote"), remote == NULL) {
        etoken_detail(detail, detail_size, "cannot read the remote configuration");
        return -2;
    }

    https = cJSON_GetObjectItem(remote, "https");
    conf_port = etoken_conf_int(https, "port", ETOKEN_DEFAULT_HTTPS_PORT);
    prefix = etoken_conf_string(https, "global_prefix", ETOKEN_DEFAULT_HTTPS_PREFIX);
    certificate = etoken_conf_string(https, "certificate", ETOKEN_DEFAULT_CERTIFICATE);
    ca_certificate = etoken_conf_string(https, "ca_certificate", ETOKEN_DEFAULT_CA);
    cJSON_Delete(remote);

    /* --- The listener certificate ------------------------------------------------------------- */

    if (leaf = w_x509_load_pem(certificate), leaf == NULL) {
        etoken_detail(detail, detail_size, "cannot read the listener certificate '%s'", certificate);
        ret = -1;
        goto end;
    }

    if (w_x509_san_is_loopback_only(leaf)) {
        /* No agent can reach it, so no token minted for it could ever work */
        etoken_detail(detail, detail_size, "certificate only names loopback");
        ret = -1;
        goto end;
    }

    if (!w_x509_san_matches(leaf, req->address)) {
        /* The agent verifies the manager's name against these entries and has nothing else to fall
         * back on: minting anyway would produce a token that fails in the field, after distribution */
        etoken_detail(detail, detail_size, "address not in certificate SAN");
        ret = -1;
        goto end;
    }

    if (literal = a2i_IPADDRESS(req->address), literal != NULL) {
        ASN1_OCTET_STRING_free(literal);
        /* Allowed, and sometimes the only option, but it ties the token to an address that a
         * re-deployment changes -- and the agent cannot follow a name it was never given */
        mwarn("Enrollment token address '%s' is an IP address: agents will not be able to verify the "
              "manager by name (document section 4.10).", req->address);
    }

    /* --- The trust anchor -------------------------------------------------------------------- */

    if (ca = w_x509_load_pem(ca_certificate), ca == NULL) {
        etoken_detail(detail, detail_size, "no ca_certificate: cannot read '%s'", ca_certificate);
        ret = -1;
        goto end;
    }

    if (!w_x509_signed_by(leaf, ca)) {
        /* A pin of a CA that did not sign the listener certificate pins nothing: the agent would
         * reject the chain it is actually offered */
        etoken_detail(detail, detail_size, "ca does not sign the listener certificate");
        ret = -1;
        goto end;
    }

    if (req->embed_ca) {
        /* The whole file, not the parsed certificate: the operator asked for what the listener is
         * verified against, and a bundle is served as it stands */
        if (out->ca_pem = w_get_file_content(ca_certificate, ETOKEN_CA_MAX_BYTES), out->ca_pem == NULL) {
            etoken_detail(detail, detail_size, "cannot read the ca_certificate '%s'", ca_certificate);
            ret = -2;
            goto end;
        }
    } else if (w_x509_spki_sha256(ca, out->pin) < 0) {
        etoken_detail(detail, detail_size, "cannot compute the pin of the ca_certificate");
        ret = -2;
        goto end;
    } else {
        out->has_pin = 1;
    }

    /* --- The endpoint ------------------------------------------------------------------------ */

    port = (req->port > 0) ? req->port : conf_port;

    if (port < 1 || port > 65535) {
        etoken_detail(detail, detail_size, "invalid port");
        ret = -1;
        goto end;
    }

    if (out->adr = etoken_adr_build(req->address, port, (req->prefix != NULL) ? req->prefix : prefix),
        out->adr == NULL) {
        etoken_detail(detail, detail_size, "internal error: the endpoint could not be built");
        ret = -2;
        goto end;
    }

    if (!etoken_adr_is_encodable(out->adr)) {
        etoken_detail(detail, detail_size, "address does not follow the endpoint grammar");
        ret = -1;
        goto end;
    }

    out->ttl = (req->ttl > 0) ? req->ttl : ETOKEN_DEFAULT_TTL;
    out->max_uses = req->max_uses;
    out->no_credential = req->no_credential;

    if (req->description != NULL) {
        os_strdup(req->description, out->description);
    }

    ret = 0;

end:
    if (ret != 0) {
        etoken_mint_free(out);
    }

    if (leaf != NULL) {
        X509_free(leaf);
    }

    if (ca != NULL) {
        X509_free(ca);
    }

    os_free(certificate);
    os_free(ca_certificate);
    os_free(prefix);

    return ret;
}
